# ADR-007: Limites de Recursos para Coexistência

## Status
Aceito

## Contexto

O VPS alvo tem ~7.8GB RAM sem swap, com ~5.9GB disponível após outros serviços (Caddy, n8n, Ollama, painéis). O Attack Detector deve coexistir sem causar OOM ou degradação dos outros serviços.

## Decisão

**Limitar o stack completo a no máximo 2.5GB de RAM** via `mem_limit` no docker-compose.prod.yml:

| Serviço | mem_limit | mem_reservation | cpus |
|---------|-----------|-----------------|------|
| PostgreSQL | 512m | 256m | 0.5 |
| Airflow Webserver | 512m | 256m | 0.5 |
| Airflow Scheduler | 384m | 192m | 0.5 |
| Spark (jobs) | 768m | 384m | 1.0 |
| Dashboard | 256m | 128m | 0.25 |
| **Total** | **~2.4GB** | **~1.2GB** | **2.75** |

Configurações de memória do Spark:
```yaml
environment:
  SPARK_DRIVER_MEMORY: 512m
  SPARK_EXECUTOR_MEMORY: 512m  # Não usado em local mode, mas definido
```

## Consequências

### Positivas
- Garante que Attack Detector não monopoliza recursos
- Deixa ~3.5GB para outros containers e sistema
- mem_reservation garante mínimo mesmo sob pressão
- Limites de CPU evitam starvation

### Negativas
- Jobs Spark podem ser mais lentos com memória limitada
- Datasets muito grandes podem falhar (mitigado por processamento incremental)
- Sem swap, OOM é fatal (mitigado pelos limites)

### Ajustes para VPS maiores
Se o VPS tiver mais RAM disponível, aumentar proporcionalmente:

```bash
# .env para VPS com mais recursos
POSTGRES_MEM_LIMIT=1g
AIRFLOW_WEB_MEM_LIMIT=768m
SPARK_MEM_LIMIT=1536m
```

## Monitoramento

Após deploy, verificar com:
```bash
docker stats --no-stream
# Confirmar que nenhum container excede seu limite
```
