# 004: Enriquecimento GeoIP

**O que construir:** Módulo que enriquece IPs com informações de geolocalização (país, cidade) usando banco GeoIP offline. Degrada graciosamente quando o banco não está disponível.

**Blocked by:** None (pode começar imediatamente, paralelo aos outros)

**Status:** ready-for-agent

- [ ] `spark/jobs/utils/geoip.py` com:
  - `GeoIPEnricher` classe que carrega DB uma vez
  - `enrich_ip(ip: str) -> dict` retorna país, cidade, lat/lon
  - Fallback para `{"country": "Unknown", "city": "Unknown"}` se DB ausente
  - Suporte a DB-IP Lite (.mmdb) e MaxMind GeoLite2 (.mmdb)
- [ ] Detecção automática de qual DB está disponível
- [ ] Path do DB configurável via env var `GEOIP_DB_PATH`
- [ ] `tests/test_geoip.py` com:
  - IP conhecido com mock DB
  - IP privado retorna "Private/Reserved"
  - DB ausente retorna fallback sem raise
  - IP malformado tratado graciosamente
- [ ] Documentação no .env.example sobre como obter DB gratuito
- [ ] Todos os testes passando
