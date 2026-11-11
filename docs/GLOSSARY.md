# Glossário

Definições dos termos utilizados neste projeto.

## Arquitetura de Dados

**Bronze Layer**
: Camada de dados brutos (raw). Logs ingeridos sem transformação, armazenados em Parquet particionado por data de ingestão.

**Silver Layer**
: Camada de dados limpos e normalizados. Eventos parseados com schema consistente, particionados por data do evento.

**Gold Layer**
: Camada de dados agregados e enriquecidos. Alertas de detecção, estatísticas, dados prontos para visualização.

**Incremental Ingestion**
: Processamento que continua de onde parou, usando checkpoints de offset para evitar reprocessar dados já ingeridos.

**Checkpoint**
: Arquivo que armazena o offset (posição em bytes) do último dado processado, permitindo retomada após interrupção.

## Segurança

**Attack Detection**
: Identificação de padrões suspeitos em logs que indicam tentativas de intrusão ou comprometimento.

**Brute Force**
: Ataque que tenta múltiplas combinações de credenciais (usuário/senha) para adivinhar acesso.

**Credential Stuffing**
: Ataque usando listas de usuário/senha vazadas de outros serviços.

**User Enumeration**
: Técnica para descobrir usuários válidos observando diferenças nas respostas de login.

**Lateral Movement**
: Movimento de atacante dentro de uma rede, pivotando entre máquinas após comprometimento inicial.

**Privilege Escalation**
: Tentativa de ganhar permissões elevadas (root, sudo) após acesso inicial.

**Success After Failure**
: Padrão onde login bem-sucedido ocorre após múltiplas falhas, indicando possível comprometimento.

**Geographic Anomaly**
: Login de localização geograficamente improvável dado histórico do usuário.

**Trusted IP**
: Endereço IP ou CIDR explicitamente permitido, geralmente do operador legítimo do sistema.

**Allowlist**
: Lista de IPs/CIDRs confiáveis que não devem gerar alertas (ou têm severidade reduzida).

**Blocklist**
: Lista de IPs que devem ser bloqueados, gerada a partir de alertas de alta severidade.

## Ferramentas

**fail2ban**
: Daemon que monitora logs e automaticamente bane IPs após falhas repetidas.

**Ban/Unban**
: Ações do fail2ban: Ban bloqueia IP via firewall, Unban remove o bloqueio após tempo configurado.

**Jail**
: Configuração do fail2ban para um serviço específico (ex: sshd, nginx).

**UFW (Uncomplicated Firewall)**
: Frontend simplificado para iptables no Ubuntu.

**Caddy**
: Servidor web/reverse proxy moderno com HTTPS automático. Alternativa ao nginx.

**auth.log**
: Arquivo de log do PAM/sshd em sistemas Debian/Ubuntu com eventos de autenticação.

**syslog**
: Sistema de logging padrão Unix, usa facility (auth, daemon) e severity (info, error).

## MITRE ATT&CK

Framework de conhecimento sobre táticas e técnicas de adversários.

**T1110** - Brute Force
**T1110.001** - Password Guessing
**T1110.004** - Credential Stuffing
**T1078** - Valid Accounts
**T1078.001** - Default Accounts
**T1078.003** - Local Accounts

## Formatos de Log

**auth.log tradicional**
: Formato syslog: `Nov 10 12:34:56 hostname sshd[pid]: message`

**auth.log ISO timestamp**
: Formato com timestamp ISO: `2024-11-10T12:34:56.123456+00:00 hostname sshd[pid]: message`

**Caddy JSON**
: Formato estruturado de access log do Caddy com campos request, response, duration, etc.

**fail2ban.log**
: Formato específico: `2024-11-10 12:34:56,789 fail2ban.actions [pid]: NOTICE [jail] Action IP`

## Operações

**Data Retention**
: Política de retenção que define por quanto tempo dados são mantidos antes de serem removidos.

**Pruning**
: Remoção de dados antigos segundo política de retenção.

**Healthcheck**
: Verificação periódica de que um serviço está funcionando corretamente.

**Coexistence**
: Capacidade do stack rodar junto com outros stacks Docker no mesmo host.

**Resource Limits**
: Restrições de CPU e memória aplicadas a containers para garantir coexistência.
