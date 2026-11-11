"""Daily DAG for refreshing threat intelligence feeds.

Downloads public blocklists for cross-referencing detected attackers.
"""

import os
from datetime import datetime, timedelta

from airflow.decorators import dag, task

DATA_PATH = os.getenv("DATA_PATH", "/opt/airflow/data")
THREAT_FEEDS_PATH = os.path.join(DATA_PATH, "threat_feeds")

FEED_URLS = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "abuse_ch_feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

default_args = {
    "owner": "attack-detector",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=10),
}


@dag(
    dag_id="refresh_threat_feeds",
    description="Daily refresh of threat intelligence feeds",
    schedule="@daily",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["attack-detector", "threat-intel"],
)
def refresh_threat_feeds():
    """Download and parse threat intelligence feeds."""

    @task
    def download_feeds(**context) -> dict:
        """Download threat feeds from public sources."""
        import requests

        os.makedirs(THREAT_FEEDS_PATH, exist_ok=True)
        results = {}

        for feed_name, url in FEED_URLS.items():
            try:
                response = requests.get(url, timeout=60)
                response.raise_for_status()

                output_file = os.path.join(THREAT_FEEDS_PATH, f"{feed_name}.txt")
                with open(output_file, "w") as f:
                    f.write(response.text)

                results[feed_name] = {
                    "status": "success",
                    "size": len(response.text),
                    "file": output_file,
                }
                print(f"Downloaded {feed_name}: {len(response.text)} bytes")

            except Exception as e:
                results[feed_name] = {"status": "error", "error": str(e)}
                print(f"Failed to download {feed_name}: {e}")

        return results

    @task
    def parse_and_consolidate(download_results: dict, **context) -> str:
        """Parse feeds and consolidate into a single blocklist."""
        import re

        all_ips = set()
        ip_pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for feed_name, result in download_results.items():
            if result.get("status") != "success":
                continue

            file_path = result.get("file")
            if not file_path or not os.path.exists(file_path):
                continue

            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    match = ip_pattern.match(line)
                    if match:
                        all_ips.add(match.group(1))

        consolidated_file = os.path.join(THREAT_FEEDS_PATH, "consolidated_blocklist.txt")
        with open(consolidated_file, "w") as f:
            f.write(f"# Consolidated threat feed - {datetime.now().isoformat()}\n")
            f.write(f"# Total IPs: {len(all_ips)}\n")
            f.write("# Sources: " + ", ".join(FEED_URLS.keys()) + "\n\n")
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")

        print(f"Consolidated {len(all_ips)} unique IPs to {consolidated_file}")
        return consolidated_file

    @task
    def convert_to_parquet(consolidated_file: str, **context) -> str:
        """Convert consolidated blocklist to Parquet for efficient joins."""
        import pandas as pd

        ips = []
        with open(consolidated_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.append(line)

        df = pd.DataFrame({"ip": ips, "is_known_threat": True})

        parquet_file = os.path.join(THREAT_FEEDS_PATH, "threat_ips.parquet")
        df.to_parquet(parquet_file, index=False)

        print(f"Wrote {len(ips)} IPs to {parquet_file}")
        return parquet_file

    downloaded = download_feeds()
    consolidated = parse_and_consolidate(downloaded)
    convert_to_parquet(consolidated)


refresh_threat_feeds()
