# 005: Job Spark Bronze Ingest

**O que construir:** Job PySpark que lê logs raw de um diretório e grava na Bronze layer como Parquet, preservando o conteúdo original com metadata de ingestão.

**Blocked by:** 001 (infra Docker), 002 (parsers para validar), 003 (sample logs para testar)

**Status:** ready-for-agent

- [ ] `spark/jobs/bronze_ingest.py` executável standalone
- [ ] Argumentos CLI: --input-path, --output-path, --log-type, --ingestion-date
- [ ] Lê arquivos de texto do input path
- [ ] Grava Parquet particionado por `ingestion_date` e `log_type`
- [ ] Schema Bronze: `raw_line`, `source_file`, `line_number`, `ingestion_timestamp`, `log_type`
- [ ] Idempotente: re-run com mesma data sobrescreve partição (não duplica)
- [ ] Spark em modo local funciona dentro do container
- [ ] Teste manual: rodar job com sample logs e verificar Parquet criado
- [ ] Documentação de como executar o job manualmente
