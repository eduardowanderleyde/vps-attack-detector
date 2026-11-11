# Memory

Notas de continuidade do `eduardowanderleyde/vps-attack-detector`. Atualizado em 11 Nov 2026, 12:11 America/Recife, com `main` em `3bacf10` (PR #75).

## O que é

Lake Bronze/Silver/Gold em PySpark, orquestrado por Airflow (LocalExecutor) e lido por um dashboard Streamlit. Detecta brute force SSH, credential stuffing, success-after-failure, varredura de path, user-agent de scanner e pico de taxa. Não bane ninguém sozinho (ADR-005): gera blocklist para revisão manual.

MVP (PRs #1–#34) já está em `main`. A v2 é o deploy no VPS real. Spec e ADRs: `docs/SPEC-v2-deploy.md`, `docs/adr/006`–`012`, `docs/GLOSSARY.md`. Revisão: `docs/reviews/v2-code-review.md`. Deploy: `DEPLOY.md`, `docs/SYSTEMD-CRON.md`.

## VPS real

Ubuntu 22.04, ~7.8 GiB RAM, sem swap, ~5.9 GiB livres antes do detector, disco ~144 GB. Dono entra por publickey. sshd em porta customizada. Logs `root:adm` 640. Caddy, não nginx. fail2ban e ufw já ativos. Apps em `/home/eduardo/apps/<nome>`.

Não mexer no VPS a menos que o usuário peça. O detector não pode duplicar ban do fail2ban nem derrubar os outros stacks.

## Onde os jobs realmente rodam

O container `spark` fica ocioso (`tail -f /dev/null`, pico medido de 8 MB). A DAG `ingest_and_detect` executa `bronze_ingest.py`, `silver_transform.py` e `gold_detect.py` **dentro do `airflow-scheduler`**, Spark em modo local.

Consequências, todas corrigidas no PR #75 (merge 11 Nov 2026, 08:11 America/Recife):

- Os logs do host têm de estar no scheduler, não no container `spark`. Produção: `LOCAL_LOG_PATH=/var/log`, montado read-only em `/opt/airflow/logs_input`. É um diretório, não um arquivo, para a rotação trocar o inode e o checkpoint perceber. O scheduler entra no grupo `adm` (`HOST_ADM_GID`, default 4).
- Os jobs fazem `sys.path.insert` da raiz do repo (três níveis acima do arquivo) e importam `spark.jobs.utils`. O mount precisa preservar o layout: `./spark` → `/opt/airflow/repo/spark`, com `SPARK_JOBS_PATH=/opt/airflow/repo/spark/jobs`. Montar em `/opt/airflow/spark_jobs` fazia a raiz calculada ser `/opt` e a ingestão quebrava com `ModuleNotFoundError`.
- Workers Python das UDFs não herdam esse `sys.path`. `PYTHONPATH=/opt/airflow/repo:...` no compose. Sem isso o silver falhava e, com `|| true`, a task ficava verde e a camada vazia.
- `./data` é do usuário do host. Airflow roda como `${AIRFLOW_UID}:0`. `scripts/deploy.sh` grava `AIRFLOW_UID=$(id -u)` no `.env`. Sem isso o job morria em `Mkdirs failed` (uid 50000 da imagem).
- `openjdk:17-slim` saiu do Docker Hub. A imagem Spark usa `eclipse-temurin:17-jre-noble`.

## Memória medida no VPS (ADR-007)

Orçamento subiu de 2.5 GB para 3 GB. Soma atual ~2.9 GB.

| Serviço | mem_limit | Por quê |
| --- | --- | --- |
| Postgres | 256m | pico 99 MB |
| Airflow webserver, 2 workers | 768m | 512m levava OOM na subida; pico ~626 MB. `AIRFLOW__WEBSERVER__WORKERS=2` |
| Airflow scheduler | 1536m | roda o driver Spark. 384m não cabia. 1536m com 6 JVMs ao mesmo tempo sofreu 8 OOM kills |
| Spark (ocioso) | 128m | pico 8 MB |
| Dashboard | 256m | |

A DAG tem `max_active_tasks=1` e `max_active_runs=1`. Heap do driver: `PYSPARK_SUBMIT_ARGS=--driver-memory 512m pyspark-shell` e `SPARK_DRIVER_MEMORY=512m`.

Silver sai 0 quando não há evento novo. A task **não** tem mais `|| true`: exceção do Spark falha a task. Teste: `tests/test_dag_failures.py`.

Checkpoints são estado de runtime (`data/checkpoints/`, `data/output/` no `.gitignore`). Não commitar: carregam o offset e a última linha lida.

## Pipeline

1. Bronze (`spark/jobs/bronze_ingest.py`): auth, nginx_access, nginx_error, docker, caddy, fail2ban. Com `--checkpoint-path` lê só o delta e só grava o checkpoint depois do Parquet. Hora sem linha nova sai 0.
2. Silver (`silver_transform.py`): auth → `ssh_events`; nginx e Caddy → `http_requests` (o segundo write é `append`); nginx error → `error_logs`; docker → `container_logs`; fail2ban → `fail2ban_events`.
3. Gold (`gold_detect.py`): alertas, `ip_stats`, `attack_summary`, e `fail2ban_events` com `currently_banned`.
4. `detect_success_after_failure` ignora `accepted_publickey` de `TRUSTED_IP_CIDRS`. Senha de IP confiável continua alerta.
5. `scripts/generate_blocklist.py` tira IPs cujo último evento fail2ban é `ban` ou `restore_ban`.

A DAG procura arquivos na raiz de `LOGS_INPUT_PATH`: `auth.log`, `nginx_*.log`, `docker.log`, `caddy.json`, `fail2ban.log`. Com `LOCAL_LOG_PATH=/var/log`, auth e fail2ban batem com o VPS. O log do Caddy no host é um diretório (`/var/log/caddy`), e a DAG ainda espera um arquivo `caddy.json` na raiz. Isso não foi alinhado no #75.

## Tickets e merges

Issues #45–#56 são os tickets 101–112 e estão fechadas. #57 (tracking da v2) e #18 (tracking do MVP) e #17 (e2e do MVP) seguem abertas. #57 fica aberta porque o deploy contínuo no VPS não é “feito e esquecido”; o código de deploy já foi exercitado no #75.

Merges em `main`, todos com merge commit, na ordem:

1. #60 CI (cache de `requirements/*.txt`, Ruff bloqueante, `ruff.toml` ignora BLE001)
2. #61 spec e ADRs (substitui #35)
3. #65 trusted IPs, fecha #49 (substitui #39)
4. #66 checkpoints, fecha #50 (substitui #40)
5. #69 retenção, fecha #51 (substitui #41)
6. #68 download GeoIP, fecha #54 (substitui #58)
7. #67 Makefile e `deploy.sh`, fecha #53 (substitui #42)
8. #70 `DEPLOY.md`, fecha #55 (substitui #43)
9. #71 systemd/cron, fecha #56 (substitui #44)
10. #62 compose de produção, fecha #45 (substitui #36). Portas com `!override`, senão o bind público do compose base continua publicado
11. #63 auth.log real, fecha #46 (substitui #37)
12. #64 parsers Caddy e fail2ban, fecha #47 e #48 (substitui #38)
13. #72 wiring bronze/silver/gold/DAG/blocklist (substitui #59)
14. #73 healthcheck do Spark: `kill -0 1` no PID 1, fecha #52
15. #74 `docs/reviews/v2-code-review.md`
16. #75 correção do deploy real, descrita acima

PRs `cursor/…-da7c` #35–#44, #58 e #59 foram fechados com link para o PR do branch limpo. O head de um PR não se renomeia.

GitHub da integração devolve 403 para label, milestone e edição de issue. A label `v2` e o milestone `v2 - Deploy` não existem. O corpo da #45 ainda é o placeholder “Test issue - will be deleted”, mas a issue está fechada.

## CI e testes

Workflow: `.github/workflows/ci.yml`. Python 3.11, Java 17 (Temurin, os testes sobem Spark local), pip cache nos três `requirements/*.txt`, pytest, Ruff sem `continue-on-error`.

No CI de `main` depois do #75 (run 43009877452, 11 Nov 2026, 08:12 America/Recife): **160 passed**. Nesta máquina, sem Docker, são 151 passed e 9 skipped: os 9 usam `docker compose config`.

GitGuardian já marcou fixture de auth como “Generic Password” quando a chave do dict continha `password` e o valor era longo. A chave ficou `iso_failed_login`. Não usar `123456` nem chave `*_password` em fixture nova.

## Como trabalhar neste repo

- Um branch por ticket, teste antes do feat, commits pequenos. Merge com merge commit, sem squash, só com CI verde (test, lint e GitGuardian).
- Branches novos deste agente: `cursor/<nome>-da7c`, salvo pedido explícito de nome limpo (`feat/101-…`, `docs/…`).
- IPs de teste: RFC 5737 (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`).
- `python3`, não `python`. Sem `pyarrow`/`pyspark` no sistema até `pip install -r requirements/spark.txt`.
- Não declarar CI verde sem o run do Actions.

## Ainda aberto

- Badge no dashboard “já banido pelo fail2ban”. O dado está em `gold/fail2ban_events`. A blocklist já exclui esses IPs. A revisão não tratou isso como defeito crítico.
- Caminho do access log do Caddy na DAG (`caddy.json` na raiz de `LOCAL_LOG_PATH`) contra o diretório real `/var/log/caddy`.
- Checkpoint só para um arquivo. Diretório continua leitura completa.
- A primeira leitura incremental carrega o delta na memória do driver.
- Healthcheck do Spark só prova que o PID 1 está vivo, e o PID 1 é o `tail`.
