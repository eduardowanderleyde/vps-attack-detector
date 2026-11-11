"""Log discovery for a directory of Caddy access logs."""

from spark.jobs.bronze_ingest import list_log_files


def test_list_log_files_reads_a_caddy_directory_and_skips_archives(tmp_path):
    caddy = tmp_path / "caddy"
    caddy.mkdir()
    (caddy / "access.log").write_text("{}\n")
    (caddy / "access.log.1").write_text("{}\n")
    (caddy / "access.log.2.gz").write_text("compressed")
    (caddy / ".hidden").write_text("nope")

    found = list_log_files(str(caddy))

    assert [path.split("/")[-1] for path in found] == ["access.log", "access.log.1"]


def test_list_log_files_returns_a_single_file(tmp_path):
    log = tmp_path / "caddy.json"
    log.write_text("{}\n")

    assert list_log_files(str(log)) == [str(log)]
