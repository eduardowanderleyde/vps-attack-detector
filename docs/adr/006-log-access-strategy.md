# ADR-006: Estratégia de Acesso a Logs do Host

## Status
Aceito

## Contexto

O VPS Attack Detector precisa ler logs do sistema host (/var/log/auth.log, /var/log/fail2ban.log) e logs de aplicação (Caddy) de dentro de containers Docker. Os arquivos de log têm permissões restritivas (root:adm 640).

Opções consideradas:
1. Bind mount read-only com group_add
2. Cópia periódica dos logs para volume acessível
3. Syslog forwarding para container
4. Docker logging driver customizado

## Decisão

**Usar bind mount read-only com `group_add: adm`** no docker-compose.prod.yml:

```yaml
services:
  spark:
    volumes:
      - /var/log/auth.log:/host-logs/auth.log:ro
      - /var/log/fail2ban.log:/host-logs/fail2ban.log:ro
      - ${CADDY_LOG_DIR:-/var/log/caddy}:/host-logs/caddy:ro
    group_add:
      - adm  # GID do grupo adm no host
```

Para Caddy logs, o usuário deve configurar o Caddyfile para escrever em um diretório montável e adicionar o container Caddy ao mesmo bind mount ou volume compartilhado.

## Consequências

### Positivas
- Acesso direto aos logs sem cópia ou delay
- Read-only garante que container não modifica logs do sistema
- Processamento incremental possível (seek por offset)
- Configuração simples no docker-compose

### Negativas
- Requer que o GID do grupo `adm` seja consistente (geralmente 4 em Ubuntu)
- Se grupo adm tiver GID diferente, precisa ajustar ou usar alternativa
- Caddy precisa de configuração adicional para emitir access logs

### Alternativa documentada
Se `group_add: adm` não funcionar (GID diferente, SELinux, etc.):

1. Criar script cron no host que copia logs para diretório acessível:
```bash
# /etc/cron.d/attack-detector-logs
*/5 * * * * root cp /var/log/auth.log /home/user/apps/vps-attack-detector/data/host-logs/ && chmod 644 /home/user/apps/vps-attack-detector/data/host-logs/*
```

2. Montar esse diretório no container sem group_add

## Notas de Implementação

- `LOCAL_LOG_PATH` no .env aponta para `/host-logs` dentro do container
- DEPLOY.md documenta verificação de GID do grupo adm
- Scripts de deploy verificam permissões antes de iniciar
