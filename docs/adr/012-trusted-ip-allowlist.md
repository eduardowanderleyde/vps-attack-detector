# ADR-012: Allowlist de IPs Confiáveis

## Status
Aceito

## Contexto

O dono do VPS faz login legítimo via publickey de IPs conhecidos. O detector "success after failure" pode gerar falsos positivos se:
1. Atacante falha muitas vezes de um IP
2. Dono faz login legítimo de outro IP logo depois
3. Sistema interpreta como "compromisso após ataque"

Além disso, logins legítimos via publickey de IPs conhecidos não devem gerar alertas críticos.

## Decisão

### 1. Variável de ambiente para CIDRs confiáveis

```bash
# .env
TRUSTED_IP_CIDRS=192.168.1.0/24,10.0.0.0/8,177.x.x.x/32
```

### 2. Função de verificação

```python
import ipaddress

def is_trusted_ip(ip: str, cidrs: list[str]) -> bool:
    """Check if IP is in any of the trusted CIDRs.
    
    Args:
        ip: IP address to check (IPv4 or IPv6)
        cidrs: List of CIDR strings (e.g., ["192.168.1.0/24", "10.0.0.0/8"])
    
    Returns:
        True if IP is in any trusted CIDR, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
    except ValueError:
        return False
```

### 3. Integração no detector

```python
def detect_success_after_failure(df, config, trusted_cidrs=None):
    # ... detecção normal ...
    
    if trusted_cidrs:
        # Remove alertas de IPs confiáveis com login via publickey
        alerts = alerts[
            ~(alerts['source_ip'].apply(lambda ip: is_trusted_ip(ip, trusted_cidrs)) &
              (alerts['auth_method'] == 'publickey'))
        ]
    
    return alerts
```

### 4. Dashboard

- Indicador visual para IPs confiáveis
- Filtro para mostrar/ocultar eventos de IPs confiáveis
- Logins de IPs confiáveis em seção separada "Atividade Legítima"

## Consequências

### Positivas
- Reduz falsos positivos para operadores legítimos
- Configurável sem código (via .env)
- Suporta ranges (CIDRs), não só IPs individuais
- Logins publickey de trusted IPs não viram alerta crítico

### Negativas
- Se atacante comprometer IP confiável, alertas serão suprimidos
- Requer manutenção da lista quando IPs mudam

### Recomendações

1. Use CIDRs específicos, não ranges muito amplos
2. Revise periodicamente a lista
3. Considere logar (não alertar) eventos de IPs confiáveis para auditoria
4. Não confie apenas na allowlist; monitore padrões anômalos mesmo de IPs confiáveis

### Formato aceito

```bash
# Exemplos válidos
TRUSTED_IP_CIDRS=192.168.1.100/32           # IP único
TRUSTED_IP_CIDRS=192.168.1.0/24             # Subnet /24
TRUSTED_IP_CIDRS=10.0.0.0/8,172.16.0.0/12   # Múltiplos CIDRs
TRUSTED_IP_CIDRS=2001:db8::/32              # IPv6
```
