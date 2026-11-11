# 015: README e Documentação Final

**O que construir:** README completo em português brasileiro com instruções de uso, arquitetura, e notas de segurança.

**Blocked by:** Todos os tickets anteriores (documentar o que existe)

**Status:** ready-for-agent

- [ ] `README.md` em pt-BR com:
  - O que é o projeto (parágrafo introdutório)
  - Diagrama de arquitetura (Mermaid)
  - Pré-requisitos (Docker, Docker Compose)
  - Como rodar o demo localmente (quick start)
  - Como configurar para VPS de produção
  - Explicação das variáveis de ambiente
  - Como acessar Airflow e Dashboard (SSH tunnel)
  - Notas de segurança (não expor portas, read-only, etc)
  - Como rodar testes
  - Estrutura de diretórios
  - Troubleshooting comum
- [ ] Makefile com targets: up, down, demo, test, logs
- [ ] Verificar que README não menciona nada hardcoded
