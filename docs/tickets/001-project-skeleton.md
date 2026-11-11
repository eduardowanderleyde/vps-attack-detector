# 001: Esqueleto do Projeto e Infraestrutura Docker

**O que construir:** A estrutura base do projeto que permite `docker compose up` subir todos os serviços (Airflow, Spark, Dashboard, PostgreSQL) e verificar que estão rodando, mesmo que sem funcionalidade real ainda. Inclui Dockerfiles, docker-compose.yml, requirements, e configuração básica.

**Blocked by:** None (pode começar imediatamente)

**Status:** ready-for-agent

- [ ] Dockerfiles funcionais para Airflow, Spark, Dashboard
- [ ] docker-compose.yml com todos os serviços e health checks
- [ ] requirements/ com dependências de cada componente
- [ ] .env.example documentado com todas as variáveis
- [ ] `docker compose up` sobe todos os containers sem erro
- [ ] Airflow webserver acessível em localhost:8085
- [ ] Spark container rodando (tail -f /dev/null por enquanto)
- [ ] Dashboard Streamlit acessível em localhost:8501 (página placeholder)
- [ ] Estrutura de diretórios data/ criada com permissões corretas
