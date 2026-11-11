.PHONY: help up down logs test demo clean build

help:
	@echo "VPS Attack Detector - Comandos disponíveis:"
	@echo ""
	@echo "  make up        - Inicia todos os serviços"
	@echo "  make down      - Para todos os serviços"
	@echo "  make logs      - Mostra logs de todos os serviços"
	@echo "  make test      - Executa testes"
	@echo "  make demo      - Executa demo com dados de exemplo"
	@echo "  make clean     - Remove dados gerados e containers"
	@echo "  make build     - Rebuilda imagens Docker"
	@echo ""

build:
	docker compose build

up:
	docker compose up -d
	@echo ""
	@echo "Serviços iniciados!"
	@echo "  Airflow UI: http://localhost:$${AIRFLOW_PORT:-8085}"
	@echo "  Dashboard:  http://localhost:$${DASHBOARD_PORT:-8501}"
	@echo ""
	@echo "Credenciais Airflow: admin / admin (altere em .env)"

down:
	docker compose down

logs:
	docker compose logs -f

logs-airflow:
	docker compose logs -f airflow-webserver airflow-scheduler

logs-spark:
	docker compose logs -f spark

logs-dashboard:
	docker compose logs -f dashboard

test:
	PYTHONPATH=. python3 -m pytest tests/ -v

test-cov:
	PYTHONPATH=. python3 -m pytest tests/ -v --cov=spark --cov-report=html

demo: up
	@echo "Aguardando serviços iniciarem..."
	@sleep 30
	@echo "Executando pipeline com dados de exemplo..."
	docker compose exec airflow-scheduler airflow dags trigger ingest_and_detect
	@echo ""
	@echo "Pipeline iniciado! Acompanhe em http://localhost:$${AIRFLOW_PORT:-8085}"
	@echo "Dashboard disponível em http://localhost:$${DASHBOARD_PORT:-8501}"

clean:
	docker compose down -v
	rm -rf data/bronze data/silver data/gold data/reports data/output
	rm -rf .pytest_cache __pycache__ spark/__pycache__ tests/__pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

status:
	docker compose ps

shell-airflow:
	docker compose exec airflow-scheduler bash

shell-spark:
	docker compose exec spark bash

blocklist:
	docker compose exec airflow-scheduler python /opt/airflow/scripts/generate_blocklist.py

# Desenvolvimento local (sem Docker)
dev-install:
	pip install -r requirements/airflow.txt -r requirements/spark.txt -r requirements/dashboard.txt pytest

dev-dashboard:
	DATA_PATH=./data streamlit run dashboard/app.py

dev-test:
	PYTHONPATH=. pytest tests/ -v
