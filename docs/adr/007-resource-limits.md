# ADR-007: Limites de Recursos para Coexistência

## Status
Aceito

## Contexto

O VPS alvo tem ~7.8GB RAM sem swap, com ~5.9GB disponível após outros serviços (Caddy, n8n, Ollama, painéis). O Attack Detector deve coexistir sem causar OOM ou degradação dos outros serviços.

## Decisão

**Limitar o stack completo a no máximo 3GB de RAM** via `mem_limit` no docker-compose.prod.yml:

| Serviço | mem_limit | mem_reservation | cpus |
|---------|-----------|-----------------|------|
| PostgreSQL | 512m | 256m | 0.5 |
| Airflow Webserver (2 workers) | 512m | 256m | 0.5 |
| Airflow Scheduler (roda os jobs Spark) | 1536m | 384m | 1.0 |
| Spark (container ocioso) | 128m | 32m | 1.0 |
| Dashboard | 256m | 128m | 0.25 |
| **Total** | **~2.9GB** | **~1.0GB** | **3.25** |

Revisão de 11/11/2026, medida no VPS: os jobs rodam no scheduler (LocalExecutor + Spark local), não no container `spark`, que teve pico de 8MB. Com 384m o scheduler não comporta o driver Spark; com 1536m e as 6 ingestões em paralelo ele ainda sofreu 8 OOM kills. Por isso a DAG roda uma task por vez (`max_active_tasks=1`), o driver usa 512m de heap (`PYSPARK_SUBMIT_ARGS`) e o webserver usa 2 workers.

Configurações de memória do Spark:
```yaml
environment:
  PYSPARK_SUBMIT_ARGS: --driver-memory 512m pyspark-shell  # no airflow-scheduler
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
