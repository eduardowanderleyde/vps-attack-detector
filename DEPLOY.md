# Deploy Guide

Este guia documenta como implantar o VPS Attack Detector em produção.

## Pré-requisitos

### Sistema
- Ubuntu 22.04 LTS (testado)
- Docker 24.0+ e Docker Compose v2
- 4GB+ RAM disponível (recomendado 6GB+)
- 10GB+ disco livre

### Permissões
- Usuário no grupo `docker`
- Acesso de leitura a `/var/log/auth.log` (grupo `adm`)

### Verificar pré-requisitos

```bash
# Docker
docker --version
docker compose version

# Grupos
groups $USER  # Deve incluir docker e adm

# Se não estiver no grupo adm:
sudo usermod -aG adm $USER
# Fazer logout/login para aplicar
```

## Deploy Rápido

```bash
# 1. Clonar repositório
git clone https://github.com/eduardowanderleyde/vps-attack-detector.git
cd vps-attack-detector

# 2. Deploy automático
./scripts/deploy.sh
```

O script:
- Cria `.env` com senhas seguras
- Cria diretórios de dados
- Verifica acesso a logs
- Baixa banco GeoIP
- Inicia containers

## Deploy Manual

### 1. Criar ambiente

```bash
# Copiar template
cp .env.example .env
chmod 600 .env

# Gerar senhas
openssl rand -base64 24  # Para POSTGRES_PASSWORD
openssl rand -base64 24  # Para AIRFLOW_ADMIN_PASSWORD
openssl rand -base64 32  # Para AIRFLOW_SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # Para AIRFLOW_FERNET_KEY
```

### 2. Configurar .env

Edite `.env` com suas configurações:

```bash
# Senhas (OBRIGATÓRIO mudar)
POSTGRES_PASSWORD=<senha-gerada>
AIRFLOW_ADMIN_PASSWORD=<senha-gerada>
AIRFLOW_SECRET_KEY=<chave-gerada>
AIRFLOW_FERNET_KEY=<chave-gerada>

# Limites de recursos (ajustar conforme seu VPS)
POSTGRES_MEM_LIMIT=512M
AIRFLOW_WEB_MEM_LIMIT=512M
SPARK_MEM_LIMIT=768M

# Caminhos dos logs do host
HOST_AUTH_LOG=/var/log/auth.log
HOST_FAIL2BAN_LOG=/var/log/fail2ban.log
HOST_CADDY_LOG_DIR=/var/log/caddy

# IPs confiáveis (seu IP de acesso)
TRUSTED_IP_CIDRS=177.x.x.x/32

# Retenção de dados
DATA_RETENTION_DAYS=30
```

### 3. Criar diretórios

```bash
mkdir -p data/{bronze,silver,gold,geoip,output,checkpoints}
```

### 4. Baixar GeoIP (opcional)

```bash
make download-geoip
# ou manualmente:
curl -sL "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > data/geoip/dbip-city-lite.mmdb
```

### 5. Validar configuração

```bash
make validate
```

Verifica:
- `.env` existe
- Portas 8085/8501 livres
- Acesso a logs

### 6. Iniciar produção

```bash
make prod-up
```

## Configuração do Caddy (se aplicável)

Se usar Caddy como reverse proxy, habilite logs JSON:

```caddyfile
{
    log {
        output file /var/log/caddy/access.log {
            roll_size 100mb
            roll_keep 10
        }
        format json
    }
}

example.com {
    # suas configs...
}
```

Reinicie Caddy:
```bash
sudo systemctl reload caddy
```

## Verificar Deploy

### Status dos containers

```bash
make prod-status
# ou
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

### Verificar logs

```bash
make prod-logs
# ou específico:
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs airflow-webserver
```

### Testar acesso

```bash
# Airflow (deve retornar HTML)
curl http://127.0.0.1:8085/health

# Dashboard (deve retornar HTML)
curl http://127.0.0.1:8501/_stcore/health
```

## Expor Serviços

Os serviços escutam apenas em `127.0.0.1` por segurança. Para acesso externo, use:

### Opção 1: SSH Tunnel (recomendado)

```bash
# No seu computador local:
ssh -L 8085:127.0.0.1:8085 -L 8501:127.0.0.1:8501 user@vps
# Acesse http://localhost:8085 e http://localhost:8501
```

### Opção 2: Reverse Proxy com Caddy

```caddyfile
airflow.example.com {
    reverse_proxy 127.0.0.1:8085
    # Adicione autenticação se expor publicamente!
}

dashboard.example.com {
    reverse_proxy 127.0.0.1:8501
}
```

## Manutenção

### Atualizar

```bash
git pull origin main
make prod-down
make prod-up
```

### Backup

```bash
# Dados Parquet
tar -czf backup-data-$(date +%Y%m%d).tar.gz data/

# PostgreSQL (metadados Airflow)
docker compose exec postgres pg_dump -U airflow airflow > backup-airflow.sql
```

### Limpeza de dados antigos

```bash
# Ver o que seria removido
make prune

# Remover (30 dias por padrão)
make prune-force
```

### Logs do sistema

```bash
# Ver últimos logs de processamento
docker compose exec airflow-webserver cat /opt/airflow/logs/scheduler/latest/*.log | tail -100
```

## Troubleshooting

### Container reiniciando

```bash
# Ver logs do container
docker compose logs --tail=50 <nome-do-container>

# Verificar recursos
docker stats --no-stream
```

### OOM (Out of Memory)

Se containers forem mortos por OOM:

1. Verificar uso de memória: `docker stats`
2. Reduzir limites em `.env`:
   ```bash
   SPARK_MEM_LIMIT=512M
   AIRFLOW_WEB_MEM_LIMIT=384M
   ```
3. Reiniciar: `make prod-restart`

### Logs não processados

1. Verificar permissões:
   ```bash
   ls -la /var/log/auth.log
   # Deve ter grupo adm e permissão r para grupo
   ```

2. Verificar GID no container:
   ```bash
   docker compose exec spark id
   # Deve mostrar grupos incluindo gid do adm
   ```

3. Verificar mount:
   ```bash
   docker compose exec spark ls -la /host-logs/
   ```

### Airflow não inicia

```bash
# Verificar banco
docker compose exec postgres pg_isready -U airflow

# Reinicializar se necessário
docker compose down -v
docker compose up -d
```

## Referências

- [ADR-006: Log Access Strategy](docs/adr/006-log-access-strategy.md)
- [ADR-007: Resource Limits](docs/adr/007-resource-limits.md)
- [ADR-008: Stack Coexistence](docs/adr/008-stack-coexistence.md)
- [ADR-009: Data Retention](docs/adr/009-data-retention.md)
- [ADR-010: Secrets Handling](docs/adr/010-secrets-handling.md)
- [SPEC-v2-deploy.md](docs/SPEC-v2-deploy.md)
