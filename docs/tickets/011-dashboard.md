# 011: Dashboard Streamlit

**O que construir:** Dashboard interativo que visualiza os dados do Gold layer: top IPs atacantes, países, tipos de ataque, timeline, alertas recentes.

**Blocked by:** 008 (Gold layer com dados)

**Status:** ready-for-agent

- [ ] `dashboard/app.py` com Streamlit:
  - Título e descrição do sistema
  - Sidebar com filtros: período, severidade mínima, tipo de ataque
  - Métricas principais: total de alertas, IPs únicos, países
- [ ] Visualizações (Plotly):
  - Top 10 IPs atacantes (bar chart)
  - Distribuição por país (mapa ou bar chart)
  - Alertas por tipo (pie chart)
  - Timeline de alertas (line chart)
  - Tabela de alertas recentes de alta severidade
- [ ] Lê Parquet do Gold layer com Pandas
- [ ] Cache com `@st.cache_data` para performance
- [ ] Refresh automático configurável
- [ ] Funciona com sample data
- [ ] Mostra mensagem amigável se não houver dados
