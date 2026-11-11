"""The ingest DAG must not hide a failed Spark job behind a green task."""

import os
import re
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAG_FILE = os.path.join(PROJECT_ROOT, "airflow", "dags", "ingest_and_detect.py")
SILVER_JOB = os.path.join(PROJECT_ROOT, "spark", "jobs", "silver_transform.py")


def test_silver_task_does_not_swallow_errors():
    source = Path(DAG_FILE).read_text(encoding="utf-8")
    silver = source.split('task_id="transform_to_silver"')[1].split("BashOperator(")[0]
    assert "|| true" not in silver


def test_silver_job_exits_zero_when_there_is_nothing_new():
    # an hour with no new events is normal; only an exception should fail the task
    source = Path(SILVER_JOB).read_text(encoding="utf-8")
    assert not re.search(r"sys\.exit\(0 if total > 0 else 1\)", source)


def test_caddy_ingest_accepts_the_host_log_directory():
    source = Path(DAG_FILE).read_text(encoding="utf-8")
    assert '[ -d "{LOGS_INPUT_PATH}/caddy" ]' in source
    assert "CADDY_CHECKPOINT" in source


def test_ingest_dag_runs_one_spark_job_at_a_time():
    # every task starts its own Spark JVM; six at once were OOM-killed in the scheduler
    source = Path(DAG_FILE).read_text(encoding="utf-8")
    decorator = source.split("@dag(")[1].split(")\ndef ")[0]
    assert "max_active_tasks=1" in decorator
    assert "max_active_runs=1" in decorator
