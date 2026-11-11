# ADR-002: Airflow com LocalExecutor

## Status
Aceito

## Contexto
Airflow suporta múltiplos executors: SequentialExecutor (um task por vez), LocalExecutor (paralelo em processos locais), CeleryExecutor (workers distribuídos), KubernetesExecutor (pods).

**Fatos:**
- VPS tem recursos limitados (~8GB RAM)
- DAGs do projeto são simples: ingestão horária, detecção, relatório diário
- Não há necessidade de escalar workers horizontalmente
- CeleryExecutor requer Redis/RabbitMQ adicional

## Decisão
Usar LocalExecutor com PostgreSQL como backend de metadados.

- Permite paralelismo de tasks (diferente do SequentialExecutor)
- Não requer broker de mensagens (diferente do CeleryExecutor)
- Footprint menor: apenas scheduler + webserver + postgres

## Alternativas Consideradas

### SequentialExecutor (SQLite)
- **Prós:** Zero dependências extras
- **Contras:** Tasks executam uma por vez; SQLite não recomendado para produção

### CeleryExecutor
- **Prós:** Escala horizontalmente; padrão em produção enterprise
- **Contras:** Requer Redis ou RabbitMQ; overhead de 3+ containers adicionais; overkill para o caso de uso

### KubernetesExecutor
- **Prós:** Isolamento perfeito de tasks
- **Contras:** Requer cluster Kubernetes; não se aplica a VPS simples

## Consequências

### Positivas
- Arquitetura simples: 2 containers Airflow + 1 PostgreSQL
- Suficiente para dezenas de DAG runs por dia
- Paralelismo adequado para os DAGs planejados

### Negativas
- Scheduler é single point of failure
- Não escala além da capacidade do VPS
- Tasks pesadas competem por recursos com o scheduler

### Mitigações
- Limitar paralelismo máximo nas configurações
- Monitorar health do scheduler
- Se necessário, migrar para CeleryExecutor com Redis é straightforward
