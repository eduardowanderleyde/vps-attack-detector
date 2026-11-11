"""Daily report DAG.

Generates a summary report of the previous day's security events.
"""

import os
from datetime import datetime, timedelta

from airflow.decorators import dag, task

DATA_PATH = os.getenv("DATA_PATH", "/opt/airflow/data")
REPORTS_PATH = os.path.join(DATA_PATH, "reports")

default_args = {
    "owner": "attack-detector",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}


@dag(
    dag_id="daily_report",
    description="Generate daily security summary report",
    schedule="0 8 * * *",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["attack-detector", "reporting"],
)
def daily_report():
    """Generate daily security report."""

    @task
    def generate_report(**context) -> str:
        """Generate markdown report from Gold layer data."""
        from datetime import datetime, timedelta

        import pandas as pd

        report_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        os.makedirs(REPORTS_PATH, exist_ok=True)

        alerts_path = os.path.join(DATA_PATH, "gold", "alerts")

        report_lines = [
            f"# Relatório de Segurança - {report_date}",
            "",
            f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        try:
            if os.path.exists(alerts_path):
                alerts_df = pd.read_parquet(alerts_path)
                day_alerts = alerts_df[alerts_df["detection_date"] == report_date]
            else:
                day_alerts = pd.DataFrame()

            report_lines.append("## Resumo")
            report_lines.append("")

            if day_alerts.empty:
                report_lines.append("Nenhum alerta detectado neste período.")
            else:
                total = len(day_alerts)
                by_severity = day_alerts.groupby("severity").size().to_dict()

                report_lines.append(f"- **Total de alertas:** {total}")
                report_lines.append(f"- **Críticos:** {by_severity.get('critical', 0)}")
                report_lines.append(f"- **Altos:** {by_severity.get('high', 0)}")
                report_lines.append(f"- **Médios:** {by_severity.get('medium', 0)}")
                report_lines.append(f"- **Baixos:** {by_severity.get('low', 0)}")
                report_lines.append("")

                report_lines.append("## Top 5 IPs Atacantes")
                report_lines.append("")
                top_ips = (
                    day_alerts.groupby("source_ip")
                    .size()
                    .sort_values(ascending=False)
                    .head(5)
                )
                for ip, count in top_ips.items():
                    report_lines.append(f"- `{ip}`: {count} alertas")
                report_lines.append("")

                report_lines.append("## Alertas por Tipo")
                report_lines.append("")
                by_type = (
                    day_alerts.groupby("alert_type").size().sort_values(ascending=False)
                )
                for alert_type, count in by_type.items():
                    report_lines.append(f"- **{alert_type}:** {count}")
                report_lines.append("")

                critical = day_alerts[day_alerts["severity"] == "critical"]
                if not critical.empty:
                    report_lines.append("## Alertas Críticos")
                    report_lines.append("")
                    for _, alert in critical.iterrows():
                        report_lines.append(
                            f"### {alert['alert_type']} - {alert['source_ip']}"
                        )
                        report_lines.append(f"- **Hora:** {alert['timestamp']}")
                        report_lines.append(f"- **Evidência:** {alert['evidence']}")
                        report_lines.append("")

        except Exception as e:
            report_lines.append(f"Erro ao gerar relatório: {e}")

        report_lines.append("---")
        report_lines.append(
            "*Relatório gerado automaticamente pelo VPS Attack Detector*"
        )

        report_content = "\n".join(report_lines)
        report_file = os.path.join(REPORTS_PATH, f"{report_date}.md")

        with open(report_file, "w") as f:
            f.write(report_content)

        print(f"Report written to {report_file}")
        return report_file

    generate_report()


daily_report()
