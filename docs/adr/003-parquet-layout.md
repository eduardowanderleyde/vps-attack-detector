# ADR-003: Layout Bronze/Silver/Gold com Parquet

## Status
Aceito

## Contexto
Precisamos armazenar logs processados de forma que:
1. Dados brutos sejam preservados (auditoria/replay)
2. Dados transformados sejam eficientes para query
3. Dashboard consiga ler dados rapidamente
4. Storage seja compacto (VPS tem disco limitado)

**Fatos:**
- Logs são texto semi-estruturado (auth.log, nginx combined, JSON docker)
- Volume diário estimado: 10-100MB de logs brutos
- Queries principais: agregações por IP, tipo de ataque, período
- Não há data warehouse ou Lakehouse (Delta/Iceberg) disponível

## Decisão
Adotar arquitetura Medallion (Bronze/Silver/Gold) com arquivos Parquet:

```
data/
├── bronze/           # Logs brutos, 1 arquivo por ingestão
│   ├── auth/
│   ├── nginx_access/
│   ├── nginx_error/
│   └── docker/
├── silver/           # Parseados e normalizados
│   ├── ssh_events/
│   ├── http_requests/
│   └── container_logs/
└── gold/             # Agregados e alertas
    ├── alerts/
    ├── ip_stats/
    └── attack_summary/
```

Particionamento:
- Bronze: por `ingestion_date`
- Silver: por `event_date` e `source_type`
- Gold: por `detection_date`

## Alternativas Consideradas

### CSV/JSON puro
- **Prós:** Simples de debugar; qualquer ferramenta lê
- **Contras:** Sem compressão; sem schema enforcement; lento para queries

### SQLite/DuckDB
- **Prós:** SQL nativo; transações
- **Contras:** Não é o formato padrão de data lakehouse; menos portável para Spark

### Delta Lake
- **Prós:** ACID transactions; time travel; merge nativo
- **Contras:** Dependência adicional; overkill para o volume; Spark OSS tem suporte limitado

## Consequências

### Positivas
- Parquet tem excelente compressão (10-20x vs JSON)
- Spark e Pandas leem nativamente
- Schema evolution básico via adição de colunas
- Formato padrão de data engineering

### Negativas
- Sem transações ACID (append-only é suficiente aqui)
- Precisa gerenciar partições manualmente
- Dados pequenos podem ter overhead de metadata

### Mitigações
- Usar `coalesce(1)` para evitar muitos arquivos pequenos
- Implementar compaction periódico se necessário
- Documentar schema de cada camada
