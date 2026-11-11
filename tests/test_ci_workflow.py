"""Contract tests for the GitHub Actions workflow.

The test job must cache pip from the requirements files that exist in this
repo, and Ruff must be allowed to fail the lint job.
"""

from pathlib import Path

import yaml

WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
REQUIREMENT_FILES = (
    "requirements/spark.txt",
    "requirements/airflow.txt",
    "requirements/dashboard.txt",
)


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def _step(job: str, name: str) -> dict:
    for step in _workflow()["jobs"][job]["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"{job} job is missing step {name!r}")


def test_pip_cache_uses_real_requirement_files():
    """setup-python must hash the requirements/*.txt files, not a missing root file."""
    step = _step("test", "Set up Python")
    options = step["with"]
    assert options["cache"] == "pip"

    dependency_path = options["cache-dependency-path"]
    text = (
        dependency_path
        if isinstance(dependency_path, str)
        else "\n".join(dependency_path)
    )
    for requirement in REQUIREMENT_FILES:
        assert requirement in text


def test_test_job_runs_pytest():
    """The test job must invoke pytest on the tests directory."""
    step = _step("test", "Run tests")
    assert "pytest tests/" in step["run"]


def test_ruff_failures_fail_the_lint_job():
    """Ruff checks in CI must not be marked continue-on-error."""
    assert "continue-on-error" not in WORKFLOW_PATH.read_text()
    lint_steps = [step.get("name") for step in _workflow()["jobs"]["lint"]["steps"]]
    assert "Check formatting" in lint_steps
    assert "Check linting" in lint_steps
