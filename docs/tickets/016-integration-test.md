# 016: Teste de Integração End-to-End

**O que construir:** Verificação final de que o pipeline completo funciona: docker compose up, DAG run, alertas no dashboard.

**Blocked by:** Todos os tickets de implementação (001-014)

**Status:** ready-for-agent

- [ ] `docker compose up -d` sobe todos os serviços sem erro
- [ ] Airflow UI acessível, DAGs visíveis e não com erro de parse
- [ ] Trigger manual do DAG `ingest_and_detect`
- [ ] DAG run completa com sucesso (todos os tasks verdes)
- [ ] Parquet criados em bronze/, silver/, gold/
- [ ] Alertas de brute force nos sample logs aparecem em gold/alerts/
- [ ] Dashboard mostra os alertas detectados
- [ ] Filtros do dashboard funcionam
- [ ] `pytest` passa todos os testes
- [ ] Blocklist pode ser gerada
- [ ] Screenshot do dashboard com alertas
- [ ] Screenshot do Airflow com DAG run sucesso
