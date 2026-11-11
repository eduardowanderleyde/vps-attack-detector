# Dados Sintéticos de Exemplo

**ATENÇÃO:** Estes são dados sintéticos gerados para teste e demonstração do sistema.
Não são logs reais de produção.

## Arquivos

- `auth.log` - Log de autenticação SSH simulado com:
  - Logins bem-sucedidos (baseline normal)
  - Brute force de vários IPs
  - Tentativas com usuários inválidos
  - Login bem-sucedido após falhas (indicador de comprometimento)

- `nginx_access.log` - Log de acesso HTTP simulado com:
  - Requisições normais 200 OK
  - Scanning de paths suspeitos (wp-admin, .env, phpmyadmin)
  - User-agents de scanners conhecidos (sqlmap, nikto, zgrab)
  - Spike de rate de um IP

- `nginx_error.log` - Log de erros nginx simulado

- `docker.log` - Log JSON de container Docker simulado

## IPs de Teste

Os seguintes IPs aparecem nos logs:

- `192.168.1.x` - IPs internos legítimos
- `10.0.0.x` - IPs internos legítimos
- `203.0.113.x` - IPs de atacantes (RFC 5737 TEST-NET-3)
- `198.51.100.x` - IPs de atacantes (RFC 5737 TEST-NET-2)
- `45.33.32.x` - IP de scanner (Shodan range)

## Cenários Cobertos

1. **SSH Brute Force:** IP 203.0.113.50 tenta 10 logins falhos em 5 minutos
2. **Credential Stuffing:** IP 198.51.100.1 tenta usuários inválidos (admin, test, guest)
3. **Path Scanning:** IP 203.0.113.100 faz 30 requisições para paths suspeitos
4. **Scanner UA:** IPs com user-agents sqlmap, nikto, zgrab
5. **Rate Spike:** IP 45.33.32.156 faz 200 requisições em 1 minuto
6. **Success After Failure:** IP 203.0.113.50 consegue login após 5 falhas (crítico)
