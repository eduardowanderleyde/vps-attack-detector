# 014: Sincronização Remota de Logs

**O que construir:** Task Airflow opcional que sincroniza logs de servidor remoto via rsync/SSH antes da ingestão.

**Blocked by:** 009 (DAG de ingestão base)

**Status:** ready-for-agent

- [ ] Task opcional no DAG `ingest_and_detect.py`
- [ ] Executa apenas se `REMOTE_HOST` configurado
- [ ] Usa rsync sobre SSH para copiar logs
- [ ] Configurável via env vars: host, user, porta, paths, chave SSH
- [ ] Chave SSH montada read-only no container
- [ ] Copia apenas arquivos modificados (rsync incremental)
- [ ] Timeout e retry para falhas de rede
- [ ] Documentação de como configurar servidor remoto
- [ ] Testa com host inexistente (falha graciosamente)
