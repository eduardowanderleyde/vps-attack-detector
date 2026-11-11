# ADR-008: Coexistência com Outros Stacks Docker

## Status
Aceito

## Contexto

O VPS já roda múltiplos stacks Docker Compose independentes (Caddy, n8n, Fleet-AI, painéis, sites). O Attack Detector deve coexistir sem conflitos de:
- Nomes de container
- Nomes de rede
- Nomes de volume
- Portas

## Decisão

### 1. Prefixo em todos os recursos

```yaml
# docker-compose.prod.yml
name: attack-detector  # Define project name explicitamente

services:
  postgres:
    container_name: attack-detector-postgres
  airflow-webserver:
    container_name: attack-detector-airflow-web
  # etc.

volumes:
  postgres-data:
    name: attack-detector-postgres-data
  airflow-logs:
    name: attack-detector-airflow-logs
```

### 2. Rede isolada

```yaml
networks:
  attack-detector-net:
    name: attack-detector-net
    driver: bridge
```

Não conectar à rede de outros stacks. Comunicação externa via portas mapeadas.

### 3. Portas em localhost apenas

```yaml
services:
  airflow-webserver:
    ports:
      - "127.0.0.1:8085:8080"  # Só localhost, não 0.0.0.0
  dashboard:
    ports:
      - "127.0.0.1:8501:8501"
```

Portas escolhidas para não conflitar:
- 8085: Airflow (não 8080 que pode estar em uso)
- 8501: Dashboard (porta padrão Streamlit)

### 4. Diretório isolado

Todos os arquivos em `/home/<user>/apps/vps-attack-detector/`:
- `docker-compose.yml`
- `docker-compose.prod.yml`
- `.env`
- `data/` (volumes locais)

## Consequências

### Positivas
- Zero conflitos com outros stacks
- `docker compose` commands afetam apenas este stack
- Fácil identificar recursos com `docker ps`, `docker volume ls`
- Remoção limpa com `docker compose down -v`

### Negativas
- Nomes mais longos nos comandos
- Precisa estar no diretório correto para comandos

### Verificação pré-deploy

O script de deploy verifica conflitos:
```bash
# Verifica se portas estão livres
ss -tlnp | grep -E ':(8085|8501)\s' && echo "ERRO: Porta em uso"

# Verifica se nomes não existem
docker ps -a --format '{{.Names}}' | grep attack-detector && echo "Containers existentes encontrados"
```
