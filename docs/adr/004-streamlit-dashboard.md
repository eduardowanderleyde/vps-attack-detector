# ADR-004: Streamlit para Dashboard

## Status
Aceito

## Contexto
O projeto precisa de um dashboard para visualizar:
- Top IPs atacantes
- Distribuição por país (se GeoIP disponível)
- Tipos de ataque ao longo do tempo
- Alertas recentes de alta severidade

**Fatos:**
- Dashboard será acessado pelo dono do VPS (1-2 usuários)
- Deve rodar no mesmo VPS com recursos limitados
- Não há necessidade de autenticação complexa (acesso via SSH tunnel)
- Dados estão em Parquet, lidos com Pandas

## Decisão
Usar Streamlit como framework de dashboard.

- Single Python file pode criar UI completa
- Lê Parquet nativamente via Pandas
- Plotly para gráficos interativos
- Footprint de memória baixo (~200-500MB)
- Deploy simples: um container

## Alternativas Consideradas

### Grafana + Prometheus
- **Prós:** Padrão de mercado para métricas; alertas nativos
- **Contras:** Requer exporters; mais complexo de configurar; métricas ≠ logs

### Metabase
- **Prós:** SQL-based; dashboards bonitos; embedável
- **Contras:** Requer PostgreSQL adicional; mais pesado (~1GB RAM); overkill

### Apache Superset
- **Prós:** Feature-rich; conecta a múltiplas fontes
- **Contras:** Muito pesado para VPS; setup complexo

### Jupyter + Voilà
- **Prós:** Flexibilidade de notebooks
- **Contras:** Mais lento; menos polido como dashboard

### HTML estático gerado
- **Prós:** Zero runtime
- **Contras:** Sem interatividade; precisa regenerar para atualizar

## Consequências

### Positivas
- Desenvolvimento rápido: Python puro, hot reload
- Interatividade: filtros, drill-down, refresh automático
- Leve: roda confortavelmente em VPS
- Flexível: fácil adicionar visualizações

### Negativas
- Não escala para muitos usuários simultâneos
- Sem autenticação built-in robusta
- Cada refresh re-lê os dados (cache manual necessário)

### Mitigações
- Binding apenas em localhost (acesso via SSH tunnel)
- Usar `@st.cache_data` para evitar re-leituras
- Documentar que não é para exposição pública
