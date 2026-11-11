# VPS Attack Detector - Makefile
# 
# Usage:
#   make help         - Show this help
#   make dev-up       - Start development stack
#   make prod-up      - Start production stack
#   make test         - Run all tests
#   make validate     - Validate configs before deploy

.PHONY: help dev-up dev-down prod-up prod-down test lint validate \
        logs clean prune setup-env download-geoip check-ports view view-data

# Default target
help:
	@echo "VPS Attack Detector - Available targets:"
	@echo ""
	@echo "Development:"
	@echo "  make dev-up        Start development stack"
	@echo "  make dev-down      Stop development stack"
	@echo "  make dev-logs      Show development logs"
	@echo ""
	@echo "Production:"
	@echo "  make prod-up       Start production stack"
	@echo "  make prod-down     Stop production stack"
	@echo "  make prod-logs     Show production logs"
	@echo "  make prod-restart  Restart production stack"
	@echo ""
	@echo "Validation:"
	@echo "  make validate      Validate configs before deploy"
	@echo "  make check-ports   Check if required ports are free"
	@echo "  make check-logs    Verify log file permissions"
	@echo ""
	@echo "Testing:"
	@echo "  make test          Run all tests"
	@echo "  make view-data     Build dashboard tables from sample logs"
	@echo "  make view          Build sample data and open the dashboard"
	@echo "  make test-parsers  Run parser tests only"
	@echo "  make test-cov      Run tests with coverage"
	@echo ""
	@echo "Maintenance:"
	@echo "  make prune         Remove old data partitions (dry-run)"
	@echo "  make prune-force   Remove old data partitions (actually delete)"
	@echo "  make clean         Remove build artifacts"
	@echo "  make download-geoip Download GeoIP database"
	@echo ""
	@echo "Setup:"
	@echo "  make setup-env     Create .env from template"
	@echo "  make init-airflow  Initialize Airflow database"

# ==============================================================================
# Development
# ==============================================================================

dev-up:
	docker compose up -d
	@echo "Development stack started"
	@echo "Airflow UI: http://localhost:8085"
	@echo "Dashboard:  http://localhost:8501"

dev-down:
	docker compose down

dev-logs:
	docker compose logs -f

dev-restart: dev-down dev-up

# ==============================================================================
# Production
# ==============================================================================

COMPOSE_PROD = docker compose -f docker-compose.yml -f docker-compose.prod.yml

prod-up: validate
	$(COMPOSE_PROD) up -d
	@echo "Production stack started"
	@echo "Airflow UI: http://127.0.0.1:8085 (localhost only)"
	@echo "Dashboard:  http://127.0.0.1:8501 (localhost only)"

prod-down:
	$(COMPOSE_PROD) down

prod-logs:
	$(COMPOSE_PROD) logs -f

prod-restart: prod-down prod-up

prod-status:
	$(COMPOSE_PROD) ps
	@echo ""
	@echo "Resource usage:"
	docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
		$$($(COMPOSE_PROD) ps -q) 2>/dev/null || true

# ==============================================================================
# Validation
# ==============================================================================

validate: check-env check-ports check-logs
	@echo "✓ All validations passed"

check-env:
	@if [ ! -f .env ]; then \
		echo "✗ .env file not found. Run 'make setup-env' first."; \
		exit 1; \
	fi
	@echo "✓ .env file exists"
	@if grep -q "CHANGE_ME" .env 2>/dev/null; then \
		echo "⚠ Warning: .env contains CHANGE_ME placeholders"; \
	fi

check-ports:
	@echo "Checking ports..."
	@if ss -tlnp 2>/dev/null | grep -q ":8085 "; then \
		echo "✗ Port 8085 (Airflow) is in use"; \
		exit 1; \
	fi
	@if ss -tlnp 2>/dev/null | grep -q ":8501 "; then \
		echo "✗ Port 8501 (Dashboard) is in use"; \
		exit 1; \
	fi
	@echo "✓ Required ports are free"

check-logs:
	@echo "Checking log file access..."
	@if [ -f /var/log/auth.log ]; then \
		if [ -r /var/log/auth.log ]; then \
			echo "✓ /var/log/auth.log is readable"; \
		else \
			echo "⚠ /var/log/auth.log exists but is not readable"; \
			echo "  Consider: sudo usermod -aG adm $$USER"; \
		fi \
	else \
		echo "⚠ /var/log/auth.log not found (OK if testing locally)"; \
	fi

# ==============================================================================
# Testing
# ==============================================================================

test:
	python3 -m pytest tests/ -v

test-parsers:
	python3 -m pytest tests/test_parsers.py -v

test-detectors:
	python3 -m pytest tests/test_detectors.py -v

test-cov:
	python3 -m pytest tests/ --cov=spark --cov=scripts --cov-report=term-missing

test-quick:
	python3 -m pytest tests/ -x -q

view-data:
	PYTHONPATH=. python3 scripts/build_view_data.py

view: view-data
	DATA_PATH=./data python3 -m streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0

# ==============================================================================
# Maintenance
# ==============================================================================

prune:
	python3 scripts/prune_old_data.py --dry-run

prune-force:
	python3 scripts/prune_old_data.py --audit-log data/retention-audit.log

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned build artifacts"

download-geoip:
	@mkdir -p data/geoip
	@echo "Downloading DB-IP City Lite database..."
	@curl -sL "https://download.db-ip.com/free/dbip-city-lite-$$(date +%Y-%m).mmdb.gz" \
		| gunzip > data/geoip/dbip-city-lite.mmdb
	@echo "✓ GeoIP database downloaded to data/geoip/dbip-city-lite.mmdb"

# ==============================================================================
# Setup
# ==============================================================================

setup-env:
	@if [ -f .env ]; then \
		echo ".env already exists. Backup and remove it first."; \
		exit 1; \
	fi
	cp .env.example .env
	@echo "Created .env from template"
	@echo "Edit .env and set secure passwords before running 'make prod-up'"

init-airflow:
	docker compose run --rm airflow-init

# ==============================================================================
# Docker helpers
# ==============================================================================

build:
	docker compose build

build-prod:
	$(COMPOSE_PROD) build

pull:
	docker compose pull

shell-spark:
	docker compose exec spark /bin/bash

shell-airflow:
	docker compose exec airflow-webserver /bin/bash
