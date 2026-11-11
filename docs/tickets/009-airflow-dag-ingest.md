# 009: DAG Airflow de Ingestão e Detecção

**O que construir:** DAG Airflow que orquestra o pipeline completo: Bronze → Silver → Gold, executando os jobs Spark. Roda a cada hora, idempotente.

**Blocked by:** 001 (Airflow funcionando), 005, 006, 008 (jobs Spark)

**Status:** ready-for-agent

- [ ] `airflow/dags/ingest_and_detect.py` com DAG:
  - Schedule: `@hourly`
  - Tasks: ingest_bronze → transform_silver → detect_gold
  - Usa BashOperator ou SparkSubmitOperator para chamar jobs
- [ ] Passa data de execução como argumento para jobs (idempotência)
- [ ] Configurável via env vars (paths, etc)
- [ ] `catchup=False` por padrão
- [ ] Retry configurado para falhas transitórias
- [ ] DAG visível no Airflow UI
- [ ] Trigger manual funciona
- [ ] Run completo com sample logs gera alertas no Gold
