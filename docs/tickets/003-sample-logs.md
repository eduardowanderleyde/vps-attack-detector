# 003: Dados Sintéticos de Exemplo

**O que construir:** Conjunto de logs sintéticos realistas para demo e testes, cobrindo todos os tipos de ataque que o sistema deve detectar. Claramente rotulados como fixtures.

**Blocked by:** 002 (parsers devem existir para validar que logs são parseáveis)

**Status:** ready-for-agent

- [ ] `data/sample_logs/auth.log` com:
  - Logins SSH bem-sucedidos (baseline normal)
  - Múltiplas falhas do mesmo IP (brute force)
  - Tentativas com usuários inválidos (credential stuffing)
  - Sucesso após múltiplas falhas (compromise indicator)
- [ ] `data/sample_logs/nginx_access.log` com:
  - Requisições normais 200 OK
  - Muitos 404s do mesmo IP (path scanning)
  - Requisições para paths suspeitos (/wp-admin, /.env, etc)
  - User-agents de scanners (sqlmap, nikto)
  - Spike de rate de um IP
- [ ] `data/sample_logs/nginx_error.log` com erros típicos
- [ ] `data/sample_logs/docker.log` com logs JSON de container
- [ ] `data/sample_logs/README.md` explicando que são dados sintéticos
- [ ] Script ou documentação de como os logs foram gerados
- [ ] Parsers do ticket 002 conseguem parsear todos os logs sem erro
