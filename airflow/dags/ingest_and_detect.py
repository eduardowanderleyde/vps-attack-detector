"""Hourly DAG for log ingestion and attack detection.

This DAG:
1. Optionally syncs logs from remote server (if configured)
2. Ingests logs to Bronze layer
3. Transforms to Silver layer
4. Runs detection to Gold layer
"""

import os
from datetime import datetime, timedelta

from airflow.decorators import dag, task
from airflow.operators.bash import BashOperator

DATA_PATH = os.getenv("DATA_PATH", "/opt/airflow/data")
SPARK_JOBS_PATH = os.getenv("SPARK_JOBS_PATH", "/opt/airflow/spark_jobs")
CONFIG_PATH = os.getenv(
    "DETECTION_CONFIG_PATH", "/opt/airflow/config/detection_rules.yaml"
)
LOGS_INPUT_PATH = os.getenv("LOGS_INPUT_PATH", "/opt/airflow/logs_input")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")
CHECKPOINT_PATH = os.getenv("CHECKPOINT_PATH", os.path.join(DATA_PATH, "checkpoints"))

REMOTE_HOST = os.getenv("REMOTE_HOST", "")
REMOTE_USER = os.getenv("REMOTE_USER", "")
REMOTE_SSH_PORT = os.getenv("REMOTE_SSH_PORT", "22")
REMOTE_LOG_PATHS = os.getenv("REMOTE_LOG_PATHS", "")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "/opt/airflow/secrets/id_rsa")

default_args = {
    "owner": "attack-detector",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}


@dag(
    dag_id="ingest_and_detect",
    description="Hourly ingestion and attack detection pipeline",
    schedule="@hourly",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["attack-detector", "ingestion", "detection"],
)
def ingest_and_detect():
    """Main DAG for log ingestion and attack detection."""

    @task
    def sync_remote_logs(**context) -> str:
        """Sync logs from remote server if configured."""
        if not REMOTE_HOST:
            return "Remote sync skipped - no REMOTE_HOST configured"

        import subprocess

        for remote_path in REMOTE_LOG_PATHS.split(","):
            remote_path = remote_path.strip()
            if not remote_path:
                continue

            local_dir = os.path.join(LOGS_INPUT_PATH, os.path.basename(remote_path))
            os.makedirs(local_dir, exist_ok=True)

            cmd = [
                "rsync",
                "-avz",
                "--timeout=60",
                "-e",
                f"ssh -p {REMOTE_SSH_PORT} -i {SSH_KEY_PATH} -o StrictHostKeyChecking=no",
                f"{REMOTE_USER}@{REMOTE_HOST}:{remote_path}",
                local_dir,
            ]

            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                print(f"Warning: rsync failed for {remote_path}: {e.stderr}")

        return "Remote sync completed"

    @task
    def get_execution_date(**context) -> str:
        """Get execution date for partitioning."""
        return context["ds"]

    ingest_auth = BashOperator(
        task_id="ingest_auth_logs",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/auth.log" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/auth.log" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type auth \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/auth.json"
        else
            echo "No auth.log found, skipping"
        fi
        """,
    )

    ingest_nginx_access = BashOperator(
        task_id="ingest_nginx_access",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/nginx_access.log" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/nginx_access.log" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type nginx_access \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/nginx_access.json"
        else
            echo "No nginx_access.log found, skipping"
        fi
        """,
    )

    ingest_nginx_error = BashOperator(
        task_id="ingest_nginx_error",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/nginx_error.log" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/nginx_error.log" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type nginx_error \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/nginx_error.json"
        else
            echo "No nginx_error.log found, skipping"
        fi
        """,
    )

    ingest_docker = BashOperator(
        task_id="ingest_docker_logs",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/docker.log" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/docker.log" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type docker \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/docker.json"
        else
            echo "No docker.log found, skipping"
        fi
        """,
    )

    ingest_caddy = BashOperator(
        task_id="ingest_caddy_logs",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/caddy.json" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/caddy.json" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type caddy \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/caddy.json"
        else
            echo "No caddy.json found, skipping"
        fi
        """,
    )

    ingest_fail2ban = BashOperator(
        task_id="ingest_fail2ban_logs",
        bash_command=f"""
        if [ -f "{LOGS_INPUT_PATH}/fail2ban.log" ]; then
            cd {SPARK_JOBS_PATH} && python bronze_ingest.py \
                --input-path "{LOGS_INPUT_PATH}/fail2ban.log" \
                --output-path "{DATA_PATH}/bronze" \
                --log-type fail2ban \
                --ingestion-date "{{{{ ds }}}}" \
                --checkpoint-path "{CHECKPOINT_PATH}/fail2ban.json"
        else
            echo "No fail2ban.log found, skipping"
        fi
        """,
    )

    transform_silver = BashOperator(
        task_id="transform_to_silver",
        bash_command=f"""
        cd {SPARK_JOBS_PATH} && python silver_transform.py \
            --bronze-path "{DATA_PATH}/bronze" \
            --silver-path "{DATA_PATH}/silver" \
            --event-date "{{{{ ds }}}}" \
            --geoip-db "{GEOIP_DB_PATH}" || true
        """,
    )

    detect_attacks = BashOperator(
        task_id="detect_attacks",
        bash_command=f"""
        cd {SPARK_JOBS_PATH} && TRUSTED_IP_CIDRS="${{TRUSTED_IP_CIDRS:-}}" python gold_detect.py \
            --silver-path "{DATA_PATH}/silver" \
            --gold-path "{DATA_PATH}/gold" \
            --detection-date "{{{{ ds }}}}" \
            --config-path "{CONFIG_PATH}"
        """,
    )

    sync = sync_remote_logs()
    _date = get_execution_date()

    ingest_tasks = [
        ingest_auth,
        ingest_nginx_access,
        ingest_nginx_error,
        ingest_docker,
        ingest_caddy,
        ingest_fail2ban,
    ]
    sync >> ingest_tasks
    ingest_tasks >> transform_silver
    transform_silver >> detect_attacks


ingest_and_detect()
