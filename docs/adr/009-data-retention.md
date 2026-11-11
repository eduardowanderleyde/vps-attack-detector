# ADR-009: Política de Retenção de Dados

## Status
Aceito

## Contexto

O pipeline gera dados Parquet em bronze/silver/gold layers. Sem limpeza, o disco eventualmente enche. Com ~144GB livres e logs de ~550KB/dia, não é urgente, mas boa prática é ter política definida.

## Decisão

**Implementar job de retenção configurável** que remove partições mais antigas que N dias:

```python
# scripts/prune_old_data.py
def prune_old_partitions(base_path: str, retention_days: int) -> list[str]:
    """Remove partitions older than retention_days.
    
    Returns list of removed partition paths for audit.
    """
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = []
    
    for layer in ['bronze', 'silver', 'gold']:
        layer_path = os.path.join(base_path, layer)
        for partition_dir in find_date_partitions(layer_path):
            partition_date = extract_date_from_partition(partition_dir)
            if partition_date < cutoff:
                shutil.rmtree(partition_dir)
                removed.append(partition_dir)
    
    return removed
```

### Configuração

```bash
# .env
DATA_RETENTION_DAYS=30  # Default: 30 dias
```

### Execução

Opção 1 - DAG Airflow (se usando Airflow scheduler):
```python
@dag(schedule="@daily", ...)
def data_retention():
    prune_task = PythonOperator(...)
```

Opção 2 - Cron (se não usando Airflow scheduler):
```bash
# crontab
0 3 * * * cd /home/user/apps/vps-attack-detector && python scripts/prune_old_data.py
```

### Auditoria

Log de remoções em `data/retention-audit.log`:
```
2024-11-10T03:00:00Z Removed: bronze/auth/ingestion_date=2024-10-10
2024-11-10T03:00:00Z Removed: silver/ssh_events/event_date=2024-10-10
2024-11-10T03:00:01Z Total removed: 15 partitions, 45MB freed
```

## Consequências

### Positivas
- Disco não enche indefinidamente
- Configurável por ambiente
- Auditoria permite verificar o que foi removido
- Pode rodar via Airflow ou cron

### Negativas
- Dados históricos perdidos após retention period
- Se precisar de histórico maior, aumentar antes que expire

### Proteções

1. Nunca remove partição do dia atual
2. Dry-run mode para verificar antes de aplicar
3. Backup recomendado antes de primeira execução
