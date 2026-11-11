# Glossário — VPS Attack Detector

Vocabulário compartilhado do projeto. Use estes termos consistentemente no código, documentação e comunicação.

## Arquitetura de Dados

### Bronze Layer (Camada Bronze)
Dados brutos ingeridos sem transformação, preservando o formato original dos logs. Armazenados em Parquet particionados por data de ingestão. Imutáveis após escrita.

### Silver Layer (Camada Silver)
Dados parseados, normalizados e enriquecidos. Timestamps convertidos para UTC, IPs enriquecidos com geolocalização (quando disponível), campos estruturados extraídos. Particionados por tipo de log e data do evento.

### Gold Layer (Camada Gold)
Dados agregados e alertas prontos para consumo. Inclui a tabela de alertas detectados, métricas agregadas por IP/país/tipo de ataque, e dados otimizados para o dashboard.

### Ingestão
Processo de captura de logs das fontes (local ou remota) para a Bronze Layer. Idempotente: re-executar não duplica dados.

### Enriquecimento
Processo de adicionar informações derivadas aos dados, especialmente geolocalização de IPs via banco GeoIP.

## Tipos de Log

### Auth Log
Log de autenticação do Linux (`/var/log/auth.log` ou via journald). Contém tentativas de login SSH, sudo, e outros eventos de autenticação.

### Access Log (nginx)
Log de requisições HTTP do nginx. Formato combined por padrão: IP, timestamp, método, path, status, user-agent.

### Error Log (nginx)
Log de erros do nginx. Inclui erros de upstream, timeouts, e erros de configuração.

### Container Log
Logs de containers Docker. Formato JSON por padrão no Docker daemon.

## Tipos de Ataque

### Brute Force SSH
Múltiplas tentativas de login falhas do mesmo IP em curta janela de tempo. Indica tentativa de adivinhar credenciais.

### Credential Stuffing
Tentativas de login com usuários inválidos (ex: root, admin, test). Indica uso de listas de credenciais conhecidas.

### Port/Path Scanning
Múltiplas requisições HTTP resultando em 404, especialmente para paths conhecidos como vulneráveis (`/wp-admin`, `/.env`, `/phpmyadmin`, etc.).

### Scanner Detection
Requisições com user-agents conhecidos de ferramentas de scanning (sqlmap, nikto, zgrab, masscan, etc.).

### Rate Spike
Pico anormal de requisições de um único IP em curto período, indicando possível DDoS ou scraping agressivo.

### Success After Failure
Login bem-sucedido após múltiplas falhas do mesmo IP. Alta severidade: pode indicar compromisso de credenciais.

## Severidade

### Crítica (Critical)
Requer atenção imediata. Exemplo: login bem-sucedido após muitas falhas.

### Alta (High)
Ataque ativo em andamento. Exemplo: brute force intenso, scanning massivo.

### Média (Medium)
Atividade suspeita que merece investigação. Exemplo: picos de rate, poucos 404s.

### Baixa (Low)
Ruído ou atividade de baixo risco. Exemplo: scanner único, bot conhecido.

## Detecção

### Threshold (Limiar)
Valor configurável que define quando uma atividade é considerada suspeita. Ex: 5 falhas de SSH em 10 minutos.

### Window (Janela)
Período de tempo usado para agregar eventos na detecção. Ex: janela de 10 minutos para brute force.

### Alert (Alerta)
Registro de atividade suspeita detectada, contendo: IP ofensor, tipo de ataque, severidade, timestamp, evidências.

### Threat Feed
Lista externa de IPs maliciosos conhecidos. Atualizada periodicamente para cross-reference.

### Blocklist
Lista de IPs a bloquear, gerada como output opcional para uso manual com fail2ban/ufw.

## Infraestrutura

### DAG (Directed Acyclic Graph)
Unidade de orquestração no Airflow. Define um pipeline de tarefas com dependências.

### LocalExecutor
Executor do Airflow que roda tarefas em processos locais. Adequado para VPS com recursos limitados.

### Spark Local Mode
Modo do Spark onde driver e executors rodam no mesmo processo JVM. Sem cluster separado.

### Backfill
Re-processamento de dados históricos. Os DAGs devem suportar sem duplicar alertas.
