# Especificação v2: Deploy em Produção

## Declaração do Problema

O VPS Attack Detector foi validado com dados sintéticos no ambiente de desenvolvimento. Agora precisa rodar em um VPS de produção real, ingerindo logs autênticos do sistema, coexistindo com outros serviços Docker Compose já em execução, e operando de forma contínua e resiliente.

**Desafios de Produção:**

1. **Recursos Compartilhados:** O VPS (~7.8GB RAM, sem swap) já roda múltiplos stacks Docker (Caddy, n8n, Ollama/Fleet-AI, painéis, sites). O Attack Detector deve usar no máximo ~2.5GB para deixar margem segura.

2. **Logs Reais:** Logs de produção têm variantes não cobertas pelos parsers atuais:
   - sshd em porta custom com formatos pam_unix
   - Mensagens de preauth e disconnect
   - Caddy JSON logs (não nginx)

3. **Integração com fail2ban:** O VPS já usa fail2ban ativo. O sistema deve mostrar quais IPs já estão banidos e não incluí-los na blocklist gerada.

4. **Operação Contínua:** A cada hora, o pipeline deve processar apenas logs novos (incremental), não reprocessar tudo desde o início.

5. **Retenção de Dados:** Parquet acumula indefinidamente. Sem política de retenção, o disco enche (~144GB livres, mas deve ser gerenciado).

6. **Segurança:** Portas não devem ser expostas publicamente. Logs devem ser montados read-only. Secrets não devem estar em código.

7. **Permissões de Logs:** Arquivos de log são `root:adm 640`. Container precisa de acesso via `group_add: adm` ou cópia read-only.

8. **Trusted IPs:** O dono legítimo usa publickey. success_after_failure deve permitir allowlist de IPs/CIDRs confiáveis.

## Ambiente Alvo (Configurável)

> **Nota:** Nenhum valor abaixo deve ser hardcoded. Todos são configuráveis via `.env` ou argumentos.

| Aspecto | Configuração Típica |
|---------|---------------------|
| OS | Ubuntu 22.04 LTS |
| RAM Total | ~7.8 GB |
| RAM Disponível | ~5.9 GB (sem swap) |
| RAM para Attack Detector | ≤ 2.5 GB (deixar margem) |
| Disco Livre | ~144 GB |
| Stacks Existentes | Caddy (reverse proxy), n8n, Ollama/Fleet-AI, painéis, sites |
| SSH | Porta não-padrão (configurável) |
| Diretório Apps | `/home/<user>/apps/<name>` |
| Logs Auth | `/var/log/auth.log` (root:adm 640, ~550KB) |
| Logs fail2ban | `/var/log/fail2ban.log` |
| Logs HTTP | Caddy JSON (precisa habilitar no Caddyfile) |
| Firewall | ufw ativo, fail2ban ativo |

### Formatos de Log Reais Observados

**auth.log** (hostname como `vpsbr-xxxx sshd[pid]:`):
```
Nov 10 12:34:56 vpsbr-xxxx sshd[12345]: Failed password for root from 203.0.113.50 port 54321 ssh2
Nov 10 12:34:57 vpsbr-xxxx sshd[12346]: Invalid user admin from 198.51.100.10 port 12345
Nov 10 12:34:58 vpsbr-xxxx sshd[12347]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5 user=test
Nov 10 12:35:00 vpsbr-xxxx sshd[12348]: Disconnected from authenticating user root 203.0.113.50 port 54321 [preauth]
Nov 10 12:35:01 vpsbr-xxxx sshd[12349]: Received disconnect from 198.51.100.10 port 12345:11: Bye Bye [preauth]
Nov 10 12:35:10 vpsbr-xxxx sshd[12350]: Accepted publickey for ubuntu from 192.168.1.1 port 54321 ssh2: ED25519 SHA256:abc123...
Nov 10 12:35:15 vpsbr-xxxx sshd[12351]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
Nov 10 12:40:00 vpsbr-xxxx sshd[12351]: pam_unix(sshd:session): session closed for user ubuntu
```

**fail2ban.log**:
```
2024-11-10 12:34:56,789 fail2ban.actions [12345]: NOTICE [sshd] Ban 203.0.113.50
2024-11-10 13:34:56,789 fail2ban.actions [12345]: NOTICE [sshd] Unban 203.0.113.50
```

**Caddy JSON logs** (quando habilitado no Caddyfile):
```json
{"level":"info","ts":1699612345.123,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.50","proto":"HTTP/2.0","method":"GET","uri":"/wp-admin","headers":{"User-Agent":["sqlmap/1.5"]}},"status":404,"duration":0.001}
```

### Dados Reais Observados

- ~1077 linhas de `Failed password` / `Invalid user` no auth.log atual
- Top atacantes: 40-77 tentativas cada
- Dono legítimo: login via publickey de IPs conhecidos

## User Stories (v2)

### Deploy e Operações

1. Como operador do VPS, quero um procedimento documentado passo-a-passo para deploy, para não cometer erros em produção.

2. Como operador do VPS, quero que o Attack Detector use no máximo 2.5GB de RAM, para deixar recursos para os outros 6+ containers já rodando.

3. Como operador do VPS, quero que todas as portas (Airflow, Dashboard) escutem apenas em 127.0.0.1, acessíveis somente via SSH tunnel.

4. Como operador do VPS, quero um comando simples (`make deploy`) para subir/atualizar o sistema em produção.

5. Como operador do VPS, quero logs e status facilmente acessíveis (`make logs`, `make status`).

6. Como operador do VPS, quero poder fazer rollback se algo der errado.

### Logs Reais

7. Como operador do VPS, quero que o sistema leia `/var/log/auth.log` read-only via bind mount com `group_add: adm`, sem modificar arquivos do sistema.

8. Como operador do VPS, quero que o parser reconheça todas as variantes reais do auth.log:
   - `Failed password for <user> from <ip> port <port> ssh2`
   - `Invalid user <user> from <ip> port <port>`
   - `pam_unix(sshd:auth): authentication failure; ... rhost=<ip> user=<user>`
   - `Disconnected from authenticating user <user> <ip> port <port> [preauth]`
   - `Received disconnect from <ip> port <port>:11: ... [preauth]`
   - `Accepted publickey for <user> from <ip> port <port> ssh2: ...`
   - `pam_unix(sshd:session): session opened/closed for user <user>`

9. Como operador do VPS, quero suporte a logs Caddy JSON (não nginx), com documentação de como habilitar access logs no Caddyfile.

10. Como operador do VPS, quero ingestão de `/var/log/fail2ban.log` para mostrar no dashboard quais IPs já foram banidos pelo fail2ban.

### Trusted IPs

11. Como operador do VPS, quero configurar uma allowlist de IPs/CIDRs confiáveis (via env) para que logins legítimos via publickey não gerem alertas de success_after_failure.

### Processamento Incremental

12. Como operador do VPS, quero que cada run do pipeline processe apenas logs novos desde a última execução, não reprocesse tudo.

13. Como operador do VPS, quero checkpoints persistidos para que reinícios não causem reprocessamento.

14. Como operador do VPS, quero que falhas parciais não corrompam o checkpoint.

### Retenção e Manutenção

15. Como operador do VPS, quero política de retenção configurável (ex: 30 dias) para dados Parquet, para não encher o disco.

16. Como operador do VPS, quero um job de pruning que rode diariamente e remova dados antigos.

17. Como operador do VPS, quero healthchecks nos containers para reinício automático em caso de falha.

### Blocklist Inteligente

18. Como operador do VPS, quero que a blocklist gerada NÃO inclua IPs que o fail2ban já baniu, para evitar duplicação.

19. Como operador do VPS, quero ver no dashboard uma indicação de "já banido pelo fail2ban" nos alertas de IPs banidos.

### GeoIP

20. Como operador do VPS, quero instruções claras de como baixar o banco GeoIP gratuito.

21. Como operador do VPS, quero um script que automatize o download do GeoIP DB.

### Alternativas de Agendamento

22. Como operador do VPS, quero a opção de usar systemd timer ou cron em vez do scheduler do Airflow, para ambientes mais simples.

## Decisões de Implementação

### Acesso a Logs (ADR-006)
- Bind mount read-only de arquivos específicos: `/var/log/auth.log:ro`, `/var/log/fail2ban.log:ro`
- Container com `group_add: adm` para ler arquivos 640
- Alternativa documentada: cópia periódica via cron se group_add não for viável
- Caddy logs: bind mount de diretório configurado no Caddyfile
- Nunca escrever nos diretórios de log do host

### Limites de Recursos (ADR-007)
- `mem_limit` e `cpus` em docker-compose.prod.yml
- Spark driver: 512MB (processamento batch pequeno)
- Spark worker: não separado (local mode)
- Airflow: 768MB (LocalExecutor)
- Dashboard: 256MB
- PostgreSQL: 512MB
- **Total: ~2.0-2.5GB** para todo o stack
- `mem_reservation` para garantir mínimo

### Coexistência com Outros Stacks (ADR-008)
- Rede Docker isolada `attack-detector-net` (não compartilhada)
- Portas bind em 127.0.0.1 apenas: `127.0.0.1:8085:8080`, `127.0.0.1:8501:8501`
- Nomes de container com prefixo `attack-detector-`
- Volumes nomeados com prefixo: `attack-detector-postgres-data`, etc.

### Retenção de Dados (ADR-009)
- Job diário de pruning (DAG ou cron)
- Configurável via `DATA_RETENTION_DAYS` (default: 30)
- Remove partições antigas de bronze/silver/gold
- Log de auditoria em `data/retention-audit.log`

### Secrets (ADR-010)
- Nunca em código ou docker-compose.yml
- `.env` no servidor (não commitado, chmod 600)
- `.env.example` com placeholders documentados
- Variáveis sensíveis: `AIRFLOW_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`

### Integração fail2ban (ADR-011)
- Parser para fail2ban.log (Ban/Unban events)
- Tabela `fail2ban_events` no Gold layer
- Dashboard mostra status de ban por IP
- Blocklist generator consulta bans ativos e exclui

### Trusted IPs (ADR-012)
- `TRUSTED_IP_CIDRS` no .env (comma-separated CIDRs)
- Detector success_after_failure ignora IPs na allowlist
- Logins publickey de trusted IPs não geram alerta crítico

## Tickets v2

### 101: Production Compose Override
docker-compose.prod.yml com:
- mem_limit/mem_reservation para cada serviço (total ≤2.5GB)
- cpus limits
- Portas bind em 127.0.0.1 apenas
- Volumes read-only para logs com group_add: adm
- Healthchecks em todos os serviços
- Restart policies (unless-stopped)
- Container name prefix

### 102: Real-World Auth Parser Variants
Expandir parse_auth_log para:
- `pam_unix(sshd:auth): authentication failure; ... rhost=<ip> user=<user>`
- `Disconnected from authenticating user <user> <ip> port <port> [preauth]`
- `Received disconnect from <ip> port <port>:11: ... [preauth]`
- `Accepted publickey for <user> from <ip> port <port> ssh2: <keytype> ...`
- `pam_unix(sshd:session): session opened/closed for user <user>`
- Testes com fixtures realistas (IPs RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)

### 103: Caddy JSON Log Parser
Novo parser parse_caddy_access para:
- Estrutura JSON do Caddy access log
- Extrai: remote_ip, method, uri, status, user_agent, timestamp
- Documentar snippet Caddyfile para habilitar access logging
- Testes com fixtures Caddy JSON

### 104: fail2ban Log Parser e Integração
- Novo parser parse_fail2ban_log (Ban/Unban events)
- Ingestão no pipeline (Bronze → Silver → Gold)
- Tabela fail2ban_events no Gold
- Dashboard: indicador "banido pelo fail2ban" nos alertas
- Blocklist: exclui IPs com ban ativo

### 105: Trusted IP Allowlist
- `TRUSTED_IP_CIDRS` env var
- Utility function `is_trusted_ip(ip, cidrs)`
- success_after_failure detector ignora trusted IPs
- Testes com CIDRs variados

### 106: Incremental Ingestion
- `CheckpointManager` class
- Persiste offset/line_number por arquivo em JSON
- Bronze ingest lê apenas linhas após checkpoint
- Checkpoint atualizado após commit bem-sucedido
- Recuperação de falhas: checkpoint só avança após sucesso

### 107: Data Retention Job
- `scripts/prune_old_data.py` standalone
- DAG diário `data_retention` (opcional)
- Lê `DATA_RETENTION_DAYS` do ambiente (default: 30)
- Remove partições antigas de bronze/silver/gold/fail2ban
- Log de auditoria com partições removidas

### 108: Healthchecks
- Healthcheck em cada serviço no docker-compose.prod.yml
- Airflow webserver: `curl -f http://localhost:8080/health`
- Airflow scheduler: process check
- Dashboard: `curl -f http://localhost:8501/_stcore/health`
- PostgreSQL: `pg_isready -U airflow`
- Spark: container running check

### 109: Deploy Scripts
- `scripts/deploy.sh` para rodar no VPS
- Makefile targets: `prod-deploy`, `prod-logs`, `prod-status`, `prod-stop`, `prod-restart`
- Verificações pré-deploy (Docker, espaço, permissões)
- Rollback via `git checkout` + redeploy

### 110: GeoIP Download Script
- `scripts/download-geoip.sh`
- Baixa DB-IP Lite (gratuito, sem registro)
- Alternativa: MaxMind com license key
- Verifica checksum
- Cria diretório se não existir

### 111: DEPLOY.md
Documentação pt-BR completa:
- Pré-requisitos (Docker, Docker Compose, SSH)
- Clone e configuração
- Configuração .env (todos os parâmetros)
- Habilitando Caddy access logs (snippet Caddyfile)
- Download GeoIP
- Deploy: `make prod-deploy`
- SSH tunnel para Airflow/Dashboard
- Verificando primeiros alertas reais
- Comandos operacionais (logs, status, restart)
- Troubleshooting comum
- Rollback

### 112: Systemd/Cron Alternative
- `docs/SCHEDULING-ALTERNATIVES.md`
- systemd timer unit files de exemplo
- crontab entries de exemplo
- Trade-offs vs Airflow scheduler
- Quando usar cada abordagem

## Seams de Teste (v2)

### Seam 1: Parsers Estendidos
- Interface: mesmas funções, mais variantes suportadas
- Testes: fixtures realistas com todas as variantes auth.log
- Testes: fixtures Caddy JSON
- Testes: fixtures fail2ban
- Localização: tests/test_parsers.py (expandido)

### Seam 2: Trusted IP Utility
- Interface: `is_trusted_ip(ip: str, cidrs: list[str]) -> bool`
- Testes: IP em CIDR, IP fora, IPv6, inválidos
- Localização: tests/test_trusted_ips.py

### Seam 3: Checkpoint Manager
- Interface: `CheckpointManager.get_offset(log_file)`, `.save_offset(log_file, offset)`
- Testes: save/load, arquivo inexistente, recuperação de corrupção
- Localização: tests/test_checkpoint.py

### Seam 4: Retention Job
- Interface: `prune_old_partitions(base_path, retention_days)`
- Testes: remove correto, preserva recente, log de auditoria
- Localização: tests/test_retention.py

### Seam 5: fail2ban Integration
- Interface: `get_active_bans(fail2ban_df) -> set[str]`
- Testes: extrai bans ativos, ignora unbans
- Localização: tests/test_fail2ban.py

## Fora do Escopo (v2)

1. **Provisionamento de VPS** — Assume VPS já existe com Docker instalado
2. **Instalação do fail2ban** — Assume já instalado e configurado
3. **Configuração do Caddy** — Documenta snippet, usuário aplica
4. **Backup automatizado** — Usuário gerencia backups do host
5. **Multi-VPS** — Um deploy por VPS, não orquestração multi-nó
6. **HTTPS/TLS** — Acesso via SSH tunnel, não exposição direta
7. **Autenticação customizada** — Usa autenticação padrão do Airflow
8. **Alertas push** — Webhook opcional documentado, não implementado
9. **Kubernetes** — Docker Compose apenas
10. **Bloqueio automático** — Gera blocklist para revisão manual (ADR-005)

## Checklist de Validação

Antes de considerar v2 completo:

- [ ] `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` funciona
- [ ] Containers respeitam limites de memória (verificar com `docker stats`)
- [ ] Total de memória < 2.5GB
- [ ] Portas não acessíveis externamente (só via SSH tunnel)
- [ ] Parser reconhece todas as variantes de auth.log reais
- [ ] Parser reconhece Caddy JSON logs
- [ ] Parser reconhece fail2ban Ban/Unban
- [ ] Ingestão incremental processa apenas logs novos
- [ ] Trusted IPs não geram alerta success_after_failure
- [ ] Blocklist exclui IPs já banidos pelo fail2ban
- [ ] Retenção remove dados > 30 dias (configurável)
- [ ] Healthchecks reiniciam containers com falha
- [ ] DEPLOY.md permite deploy por pessoa sem contexto prévio
- [ ] Todos os testes passam
- [ ] CI verde
