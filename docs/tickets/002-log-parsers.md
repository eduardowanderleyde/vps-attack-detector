# 002: Parsers de Logs

**O que construir:** Módulo de parsers que converte linhas de texto de cada tipo de log em dicts estruturados Python. Interface pura (string in, dict out), sem dependências de Spark ainda. Totalmente testável unitariamente.

**Blocked by:** None (pode começar imediatamente, paralelo ao 001)

**Status:** ready-for-agent

- [ ] `spark/jobs/utils/parsers.py` com funções:
  - `parse_auth_log(line: str) -> dict | None`
  - `parse_nginx_access(line: str) -> dict | None`
  - `parse_nginx_error(line: str) -> dict | None`
  - `parse_docker_json(line: str) -> dict | None`
- [ ] Cada parser extrai: timestamp, IP (quando presente), campos específicos do tipo
- [ ] Parsers retornam None para linhas não reconhecidas (não raise)
- [ ] Timestamps parseados para datetime (naive, timezone será normalizado depois)
- [ ] `tests/test_parsers.py` com testes para:
  - Linha válida típica de cada tipo
  - Linha malformada (retorna None)
  - Edge cases (IPs IPv6, timestamps diferentes)
- [ ] Todos os testes passando
