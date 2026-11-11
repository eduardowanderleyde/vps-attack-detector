# 010: Download de Threat Feeds

**O que construir:** DAG Airflow diário que baixa feeds públicos de IPs maliciosos e armazena para cross-reference na detecção.

**Blocked by:** 001 (Airflow funcionando)

**Status:** ready-for-agent

- [ ] `airflow/dags/refresh_threat_feeds.py` com DAG:
  - Schedule: `@daily`
  - Task: download_feeds
- [ ] Baixa FireHOL level1 ou abuse.ch feeds (URLs configuráveis)
- [ ] Salva em `data/threat_feeds/` com timestamp
- [ ] Parseia para formato padronizado (lista de IPs)
- [ ] Grava Parquet para fácil join no Spark
- [ ] Degrada graciosamente se download falhar (usa último disponível)
- [ ] DAG visível e executável no Airflow UI
