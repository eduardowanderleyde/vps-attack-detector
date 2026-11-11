# 008: Job Spark Gold Detect

**O que construir:** Job PySpark que lê Silver, aplica todas as regras de detecção, e grava alertas na Gold layer. Também gera agregações para o dashboard.

**Blocked by:** 006 (Silver layer), 007 (detectores)

**Status:** ready-for-agent

- [ ] `spark/jobs/gold_detect.py` executável standalone
- [ ] Argumentos CLI: --silver-path, --gold-path, --config-path, --detection-date
- [ ] Lê Parquet Silver filtrado por data
- [ ] Aplica cada detector do módulo detectors
- [ ] Combina alertas de todos os detectores
- [ ] Deduplica alertas (mesmo IP + tipo + janela = 1 alerta)
- [ ] Grava `gold/alerts/` particionado por `detection_date`
- [ ] Grava `gold/ip_stats/` com agregações por IP
- [ ] Grava `gold/attack_summary/` com contagens por tipo/severidade
- [ ] Schema Alerts: `alert_id`, `alert_type`, `severity`, `source_ip`, `country`, `city`, `timestamp`, `evidence`, `detection_date`
- [ ] Teste manual com Silver de sample logs
- [ ] Verificar que alertas esperados são gerados
