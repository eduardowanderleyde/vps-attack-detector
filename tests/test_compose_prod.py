"""Tests for production Docker Compose configuration.

Validates docker-compose.prod.yml according to ADRs 006, 007, 008.
"""

import os
import shutil
import subprocess

import pytest
import yaml

COMPOSE_FILE = "docker-compose.yml"
COMPOSE_PROD_FILE = "docker-compose.prod.yml"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def docker_available() -> bool:
    """Check if docker command is available."""
    return shutil.which("docker") is not None


def load_compose_config() -> dict:
    """Load merged docker-compose configuration."""
    if not docker_available():
        pytest.skip("Docker not available")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            COMPOSE_FILE,
            "-f",
            COMPOSE_PROD_FILE,
            "config",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"docker compose config failed: {result.stderr}")
    return yaml.safe_load(result.stdout)


def _compose_loader() -> type[yaml.SafeLoader]:
    """Safe YAML loader that accepts Compose's !override tag."""

    class ComposeLoader(yaml.SafeLoader):
        pass

    def construct_override(loader: yaml.SafeLoader, node: yaml.Node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    ComposeLoader.add_constructor("!override", construct_override)
    return ComposeLoader


def port_binds_localhost(port: object) -> bool:
    """True when a compose port string or config dict binds 127.0.0.1."""
    if isinstance(port, str):
        return port.startswith("127.0.0.1:")
    if isinstance(port, dict):
        return port.get("host_ip") == "127.0.0.1"
    return False


def volume_text(volume: object) -> str:
    """Normalize a compose volume string or config dict for assertions."""
    if isinstance(volume, str):
        return volume
    if isinstance(volume, dict):
        source = volume.get("source", "")
        target = volume.get("target", "")
        mode = ":ro" if volume.get("read_only") else ""
        return f"{source}:{target}{mode}"
    return str(volume)


def load_prod_yaml() -> dict:
    """Load docker-compose.prod.yml directly (no merge)."""
    path = os.path.join(PROJECT_ROOT, COMPOSE_PROD_FILE)
    with open(path) as f:
        return yaml.load(f, Loader=_compose_loader())


class TestResourceLimits:
    """ADR-007: Resource limits for VPS coexistence."""

    def test_all_services_have_memory_limits(self):
        """Every service must have a memory limit."""
        config = load_compose_config()
        services = config.get("services", {})

        for name, svc in services.items():
            if name == "airflow-init":
                continue
            deploy = svc.get("deploy", {})
            limits = deploy.get("resources", {}).get("limits", {})
            assert "memory" in limits, f"Service {name} missing memory limit"

    def test_total_memory_under_limit(self):
        """Total memory limits should be under 2.5GB."""
        config = load_compose_config()
        services = config.get("services", {})

        total_mb = 0
        for name, svc in services.items():
            if name == "airflow-init":
                continue
            deploy = svc.get("deploy", {})
            limits = deploy.get("resources", {}).get("limits", {})
            mem = limits.get("memory", "0")
            total_mb += parse_memory_mb(mem)

        assert total_mb <= 2500, f"Total memory {total_mb}MB exceeds 2.5GB limit"

    def test_spark_has_cpu_limit(self):
        """Spark should have CPU limit to avoid starvation."""
        config = load_compose_config()
        spark = config.get("services", {}).get("spark", {})
        deploy = spark.get("deploy", {})
        limits = deploy.get("resources", {}).get("limits", {})
        assert "cpus" in limits, "Spark missing CPU limit"


class TestLogAccess:
    """ADR-006: Log access strategy with group_add."""

    def test_spark_has_group_add(self):
        """Spark service should have group_add for adm group."""
        config = load_compose_config()
        spark = config.get("services", {}).get("spark", {})
        group_add = spark.get("group_add", [])
        assert len(group_add) > 0, "Spark missing group_add for log access"

    def test_host_log_mounts_are_readonly(self):
        """Host log mounts should be read-only."""
        config = load_compose_config()
        spark = config.get("services", {}).get("spark", {})
        volumes = spark.get("volumes", [])

        host_log_mounts = [v for v in volumes if "/host-logs" in volume_text(v)]
        assert len(host_log_mounts) > 0, "No host log mounts found"

        for mount in host_log_mounts:
            assert ":ro" in volume_text(mount), f"Host log mount not read-only: {mount}"


class TestCoexistence:
    """ADR-008: Docker stack coexistence strategy."""

    def test_volumes_have_explicit_names(self):
        """Volumes should have explicit names with prefix."""
        config = load_compose_config()
        volumes = config.get("volumes", {})

        for name, vol_config in volumes.items():
            if vol_config is None:
                continue
            vol_name = vol_config.get("name", "")
            assert vol_name.startswith("attack-detector-"), (
                f"Volume {name} should have 'attack-detector-' prefix, got '{vol_name}'"
            )

    def test_network_has_explicit_name(self):
        """Network should have explicit name."""
        config = load_compose_config()
        networks = config.get("networks", {})

        for name, net_config in networks.items():
            if net_config is None:
                continue
            net_name = net_config.get("name", "")
            assert "attack-detector" in net_name, (
                f"Network {name} should have 'attack-detector' in name"
            )

    def test_web_ports_are_localhost_only(self):
        """Web-facing ports should bind to localhost only."""
        config = load_compose_config()
        services = config.get("services", {})

        for name in ["airflow-webserver", "dashboard"]:
            svc = services.get(name, {})
            ports = svc.get("ports", [])
            for port in ports:
                assert port_binds_localhost(port), (
                    f"Service {name} port {port} should bind to 127.0.0.1"
                )


class TestHealthchecks:
    """Services should have healthchecks."""

    def test_critical_services_have_healthchecks(self):
        """Critical services need healthchecks."""
        config = load_compose_config()
        services = config.get("services", {})

        critical = [
            "postgres",
            "airflow-webserver",
            "airflow-scheduler",
            "spark",
            "dashboard",
        ]
        for name in critical:
            svc = services.get(name, {})
            assert "healthcheck" in svc, f"Service {name} missing healthcheck"


def parse_memory_mb(mem_str: str) -> int:
    """Parse memory string like '512M' or '1G' to megabytes."""
    mem_str = str(mem_str).upper().strip()
    if mem_str.endswith("G"):
        return int(float(mem_str[:-1]) * 1024)
    elif mem_str.endswith("M"):
        return int(float(mem_str[:-1]))
    elif mem_str.endswith("K"):
        return int(float(mem_str[:-1]) / 1024)
    else:
        return int(mem_str) // (1024 * 1024)


class TestProdYamlStructure:
    """Tests that don't require Docker - validate YAML structure."""

    def test_prod_yaml_is_valid(self):
        """docker-compose.prod.yml should be valid YAML."""
        config = load_prod_yaml()
        assert config is not None
        assert "services" in config

    def test_prod_yaml_has_expected_services(self):
        """Prod override should have expected service overrides."""
        config = load_prod_yaml()
        services = config.get("services", {})
        expected = [
            "postgres",
            "airflow-webserver",
            "airflow-scheduler",
            "spark",
            "dashboard",
        ]
        for svc in expected:
            assert svc in services, f"Missing service override: {svc}"

    def test_spark_has_host_log_volumes(self):
        """Spark should have host log volume mounts defined."""
        config = load_prod_yaml()
        spark = config.get("services", {}).get("spark", {})
        volumes = spark.get("volumes", [])

        host_log_mounts = [v for v in volumes if "/host-logs" in str(v)]
        assert len(host_log_mounts) >= 3, (
            f"Expected at least 3 host log mounts (auth, fail2ban, caddy), got {len(host_log_mounts)}"
        )

    def test_spark_has_group_add_in_yaml(self):
        """Spark should have group_add defined."""
        config = load_prod_yaml()
        spark = config.get("services", {}).get("spark", {})
        assert "group_add" in spark, "Spark missing group_add"

    def test_volumes_have_names(self):
        """Volumes should have explicit names."""
        config = load_prod_yaml()
        volumes = config.get("volumes", {})

        for name, vol_config in volumes.items():
            assert vol_config is not None, f"Volume {name} has no config"
            assert "name" in vol_config, f"Volume {name} missing explicit name"
            assert vol_config["name"].startswith("attack-detector-"), (
                f"Volume {name} name should start with 'attack-detector-'"
            )

    def test_network_has_name(self):
        """Network should have explicit name."""
        config = load_prod_yaml()
        networks = config.get("networks", {})

        for name, net_config in networks.items():
            assert net_config is not None, f"Network {name} has no config"
            assert "name" in net_config, f"Network {name} missing explicit name"

    def test_webserver_port_is_localhost(self):
        """Web-facing ports should bind to localhost."""
        config = load_prod_yaml()

        for svc_name in ["airflow-webserver", "dashboard"]:
            svc = config.get("services", {}).get(svc_name, {})
            ports = svc.get("ports", [])
            for port in ports:
                assert str(port).startswith("127.0.0.1:"), (
                    f"Service {svc_name} port {port} should bind to 127.0.0.1"
                )

    def test_spark_has_env_vars_for_production(self):
        """Spark should have production environment variables."""
        config = load_prod_yaml()
        spark = config.get("services", {}).get("spark", {})
        env = spark.get("environment", [])

        env_dict = {}
        for item in env:
            if "=" in item:
                key, val = item.split("=", 1)
                env_dict[key] = val

        assert "HOST_LOG_PATH" in env_dict, "Spark missing HOST_LOG_PATH env"
        assert "TRUSTED_IP_CIDRS" in env_dict, "Spark missing TRUSTED_IP_CIDRS env"
        assert "DATA_RETENTION_DAYS" in env_dict, (
            "Spark missing DATA_RETENTION_DAYS env"
        )

    def test_spark_healthcheck_checks_the_container_is_running(self):
        """Ticket 108: Spark has no HTTP health URL, so probe PID 1."""
        spark = load_prod_yaml().get("services", {}).get("spark", {})
        health = spark.get("healthcheck", {})
        command = health.get("test", [])
        text = " ".join(command) if isinstance(command, list) else str(command)
        assert "kill -0 1" in text
