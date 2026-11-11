# 006: Job Spark Silver Transform

**O que construir:** Job PySpark que lê Bronze, aplica parsers para extrair campos estruturados, normaliza timestamps para UTC, e opcionalmente enriquece IPs com GeoIP. Grava na Silver layer.

**Blocked by:** 005 (Bronze layer deve existir), 002 (parsers), 004 (GeoIP)

**Status:** ready-for-agent

- [ ] `spark/jobs/silver_transform.py` executável standalone
- [ ] Argumentos CLI: --bronze-path, --silver-path, --event-date, --geoip-db (opcional)
- [ ] Lê Parquet Bronze filtrado por data
- [ ] Aplica parser apropriado baseado em `log_type`
- [ ] UDF Spark para aplicar parsers em batch
- [ ] Normaliza timestamps para UTC (assume timezone do servidor configurável)
- [ ] Enriquece IPs se GeoIP DB disponível (degrada se não)
- [ ] Schema Silver: campos parseados + `event_timestamp_utc`, `source_ip`, `country`, `city`
- [ ] Particionado por `event_date` e `log_type`
- [ ] Linhas não parseáveis vão para partição `_errors` (não descartadas)
- [ ] Teste manual com dados Bronze dos sample logs
