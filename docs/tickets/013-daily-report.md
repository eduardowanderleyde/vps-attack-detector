# 013: DAG de Relatório Diário

**O que construir:** DAG Airflow que gera relatório diário resumido dos eventos de segurança.

**Blocked by:** 008 (Gold layer), 011 (pode reusar lógica)

**Status:** ready-for-agent

- [ ] `airflow/dags/daily_report.py` com DAG:
  - Schedule: `0 8 * * *` (8h da manhã)
  - Task: generate_report
- [ ] Lê alertas do dia anterior
- [ ] Gera sumário:
  - Total de alertas por severidade
  - Top 5 IPs atacantes
  - Top 3 tipos de ataque
  - Alertas críticos (lista completa)
- [ ] Salva relatório em `data/reports/YYYY-MM-DD.md`
- [ ] Opcional: envia para webhook se configurado
- [ ] DAG visível e executável no Airflow UI
