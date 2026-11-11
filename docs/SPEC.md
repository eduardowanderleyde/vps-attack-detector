# Especificação: VPS Attack Detector

## Declaração do Problema

O dono de um VPS Ubuntu 22.04 (HostGator Brasil, ~8GB RAM) roda serviços de produção com SSH em porta não-padrão, apps Docker Compose atrás de nginx, e serviços nas portas 8000, 8080, 8081. O servidor está exposto à internet e recebe constantemente tentativas de ataque: brute force SSH, scanning de paths vulneráveis, bots maliciosos.

**Problema:** Não há visibilidade centralizada sobre esses ataques. Os logs existem mas estão espalhados, não são correlacionados, e não geram alertas. O dono não sabe quem está atacando, de onde, com que frequência, ou se algum ataque teve sucesso.

**Impacto:** Sem essa visibilidade, compromissos de segurança podem passar despercebidos. Não é possível tomar decisões informadas sobre bloqueios ou hardening.

## Solução

Um pipeline de data engineering que:

1. **Ingere** logs de múltiplas fontes (SSH auth, nginx, Docker)
2. **Processa** com Apache Spark em arquitetura Bronze/Silver/Gold
3. **Detecta** padrões de ataque conhecidos com regras configuráveis
4. **Visualiza** em um dashboard Streamlit com top atacantes, países, tipos, timeline
5. **Exporta** opcionalmente uma blocklist para uso manual com fail2ban/ufw

Tudo orquestrado por Apache Airflow, rodando em Docker Compose dimensionado para o VPS.

## User Stories

1. Como dono do VPS, quero ver de quais IPs estão vindo mais tentativas de ataque, para decidir se devo bloqueá-los manualmente.

2. Como dono do VPS, quero ser alertado quando houver um login SSH bem-sucedido após muitas falhas, porque isso pode indicar comprometimento de credenciais.

3. Como dono do VPS, quero ver de quais países vêm os ataques, para considerar bloqueios geográficos.

4. Como dono do VPS, quero visualizar a tendência de ataques ao longo do tempo, para entender se a exposição está aumentando.

5. Como dono do VPS, quero que os thresholds de detecção sejam configuráveis, porque meu tráfego legítimo pode ter padrões específicos.

6. Como dono do VPS, quero que o sistema rode sem intervenção após configurado, processando logs automaticamente a cada hora.

7. Como dono do VPS, quero poder testar o sistema com dados de exemplo antes de apontar para logs reais, para validar que funciona.

8. Como dono do VPS, quero que o sistema degrade graciosamente se o banco GeoIP não estiver disponível, mostrando "desconhecido" em vez de falhar.

9. Como dono do VPS, quero uma blocklist sugerida que eu possa revisar e aplicar manualmente, nunca automática.

10. Como dono do VPS, quero que o sistema consuma poucos recursos, pois o VPS já roda outros serviços.

11. Como dono do VPS, quero poder re-processar dados históricos (backfill) sem duplicar alertas.

12. Como dono do VPS, quero cross-reference dos IPs detectados com feeds de ameaças públicos, para priorizar IPs já conhecidos como maliciosos.

13. Como dono do VPS, quero documentação em português explicando como configurar e rodar.

14. Como dono do VPS, quero poder puxar logs de outro servidor via SSH/rsync, caso eu centralize logs de múltiplos VPS.

15. Como dono do VPS, quero detectar scanning de paths comuns como `/wp-admin`, `/.env`, `/phpmyadmin`, que indicam bots procurando vulnerabilidades.

16. Como dono do VPS, quero detectar user-agents de ferramentas de scan conhecidas como sqlmap, nikto, zgrab.

17. Como dono do VPS, quero um relatório diário resumido com os principais eventos de segurança.

## Decisões de Implementação

### Fontes de Dados
- **Auth logs:** `/var/log/auth.log` ou export de journald
- **Nginx logs:** `access.log` (formato combined), `error.log`
- **Docker logs:** JSON logs do daemon ou export via `docker logs`
- **Ingestão local:** Diretório montado no container
- **Ingestão remota (opcional):** rsync/SSH pull configurável via env vars

### Módulos Principais

1. **Parsers** (`spark/jobs/utils/parsers.py`)
   - `parse_auth_log()`: regex para auth.log format
   - `parse_nginx_access()`: regex para combined format
   - `parse_nginx_error()`: regex para error format
   - `parse_docker_json()`: parse de JSON logs

2. **GeoIP** (`spark/jobs/utils/geoip.py`)
   - `enrich_ip()`: lookup em DB-IP Lite ou MaxMind GeoLite2
   - Fallback para `{"country": "Unknown", "city": "Unknown"}` se DB não disponível

3. **Detectors** (`spark/jobs/utils/detectors.py`)
   - `detect_ssh_brute_force()`: N falhas por IP em janela
   - `detect_credential_stuffing()`: logins com usuários inválidos
   - `detect_path_scanning()`: N 404s em paths suspeitos
   - `detect_scanner_ua()`: match de user-agents conhecidos
   - `detect_rate_spike()`: requisições acima de threshold
   - `detect_success_after_failure()`: sucesso após falhas (crítico)

4. **Spark Jobs** (`spark/jobs/`)
   - `bronze_ingest.py`: raw logs → Bronze (Parquet)
   - `silver_transform.py`: Bronze → Silver (parseado, normalizado, enriquecido)
   - `gold_detect.py`: Silver → Gold (alertas detectados, agregações)

5. **Airflow DAGs** (`airflow/dags/`)
   - `ingest_and_detect.py`: horário, ingere + processa + detecta
   - `refresh_threat_feeds.py`: diário, baixa feeds públicos
   - `daily_report.py`: diário, gera sumário

6. **Dashboard** (`dashboard/app.py`)
   - Lê Gold layer com Pandas
   - Plotly para visualizações
   - Filtros por período, severidade, tipo

7. **Blocklist Generator** (`scripts/generate_blocklist.py`)
   - Lê alertas de alta severidade
   - Gera arquivo texto com IPs únicos

### Configuração
- Todas as credenciais e paths via variáveis de ambiente
- `.env.example` documentado com todos os parâmetros
- `config/detection_rules.yaml` para thresholds ajustáveis

### Dados de Exemplo
- `data/sample_logs/` com logs sintéticos realistas
- Claramente rotulados como fixtures de teste
- Incluem exemplos de cada tipo de ataque

## Decisões de Teste

### O que faz um bom teste
- Testa comportamento externo através de interfaces públicas
- Não depende de detalhes de implementação
- Sobrevive a refatorações que preservam comportamento
- Lê como especificação: nome descreve a capacidade testada

### Seams (Pontos de Teste)

**Seam 1: Parsers**
- Interface: funções que recebem string de log e retornam dict estruturado
- Testes: cada parser com linhas válidas, malformadas, edge cases
- Localização: `tests/test_parsers.py`

**Seam 2: Detectors**
- Interface: funções que recebem DataFrame e config, retornam DataFrame de alertas
- Testes: cada detector com dados que devem/não devem gerar alerta
- Localização: `tests/test_detectors.py`

**Seam 3: GeoIP Enrichment**
- Interface: função que recebe IP e retorna dict com país/cidade
- Testes: IP válido com DB, IP válido sem DB (fallback), IP inválido
- Localização: `tests/test_geoip.py`

**Seam 4: Pipeline Integration (opcional)**
- Interface: DAG run end-to-end com sample logs
- Testes: alertas esperados aparecem no Gold layer
- Localização: `tests/test_integration.py`

### Prior Art
- Framework: pytest
- Fixtures: pytest fixtures para DataFrames de teste
- Mocking: unittest.mock para GeoIP DB

## Fora do Escopo

1. **Bloqueio automático de IPs** — ADR-005 documenta que o sistema é de detecção, não prevenção

2. **Análise de payload HTTP** — Apenas headers e metadata, não body de requisições

3. **Machine Learning** — Regras baseadas em threshold, não anomaly detection com ML

4. **Multi-tenancy** — Um dashboard por VPS, não plataforma multi-usuário

5. **Retenção/Purge automático** — Usuário gerencia manualmente o espaço em disco

6. **Alertas push (email/Slack)** — Webhook opcional documentado, mas não implementado no MVP

7. **Logs de aplicação customizados** — Apenas auth, nginx, docker padrão

8. **Windows Event Logs** — Apenas Linux

## Notas Adicionais

### Segurança
- Dashboard e Airflow devem fazer bind apenas em localhost
- Acesso via SSH tunnel: `ssh -L 8501:localhost:8501 user@vps`
- Nunca expor portas 8085 (Airflow) ou 8501 (Dashboard) publicamente
- Logs são lidos read-only; nenhuma escrita nos sistemas fonte

### Performance
- Spark processa em batches, não streaming
- Dashboard usa cache para evitar re-leitura a cada refresh
- Configurações de memória documentadas para VPS de 8GB

### Idempotência
- Bronze layer usa timestamp de ingestão como partição
- Silver/Gold usam upsert lógico baseado em hash de evento
- Re-run de DAG não duplica dados
