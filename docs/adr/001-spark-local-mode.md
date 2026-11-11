# ADR-001: Spark em Modo Local para VPS de 8GB

## Status
Aceito

## Contexto
O projeto será executado em um VPS Ubuntu 22.04 com aproximadamente 8GB de RAM, que já hospeda outros serviços (Docker Compose apps atrás de nginx). Precisamos processar logs com Spark/PySpark, mas um cluster Spark tradicional consumiria mais recursos do que o disponível.

**Fatos:**
- VPS tem ~8GB RAM total
- Outros serviços já consomem parte da RAM (nginx, Docker apps em portas 8000, 8080, 8081)
- Volume de logs esperado: dezenas a centenas de MB por dia (não big data)
- Spark é requisito do projeto para demonstrar pipeline de data engineering

## Decisão
Usar Spark em modo local (`local[*]`) com limites de memória conservadores:
- Driver memory: 1GB
- Executor memory: 1GB  
- Container limit: 2.5GB

O Spark rodará como um container "worker" que processa jobs submetidos pelo Airflow, não como um cluster standalone.

## Alternativas Consideradas

### Cluster Spark Standalone
- **Prós:** Mais próximo de produção enterprise
- **Contras:** Master + Worker consumiriam >4GB; overhead desnecessário para o volume de dados

### Pandas/DuckDB apenas
- **Prós:** Menor footprint de memória
- **Contras:** Não demonstra skills de Spark/data engineering; menos escalável se logs crescerem

### Spark no mesmo container do Airflow
- **Prós:** Um container a menos
- **Contras:** Mais difícil gerenciar memória; Airflow scheduler já consome recursos

## Consequências

### Positivas
- Footprint de memória previsível e limitado
- Jobs Spark executam sem precisar de cluster
- Fácil escalar para cluster se migrar para servidor maior

### Negativas
- Paralelismo limitado a cores do VPS
- Não adequado para processar TBs de dados (não é o caso de uso)
- Precisa tuning cuidadoso de memória se outros serviços crescerem

### Mitigações
- Documentar configurações de memória no `.env.example`
- Monitorar uso de memória com `docker stats`
- Processar dados em batches menores se necessário
