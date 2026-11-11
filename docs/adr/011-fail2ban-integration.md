# ADR-011: Integração com fail2ban

## Status
Aceito

## Contexto

O VPS já usa fail2ban para banir IPs automaticamente. O Attack Detector deve:
1. Mostrar no dashboard quais IPs já foram banidos
2. Não incluir IPs já banidos na blocklist gerada
3. Nunca duplicar ou conflitar com fail2ban

## Decisão

### 1. Ingestão de fail2ban.log

Novo parser para extrair eventos Ban/Unban:

```python
def parse_fail2ban_log(line: str) -> dict | None:
    """Parse fail2ban log line.
    
    Formats:
    2024-11-10 12:34:56,789 fail2ban.actions [12345]: NOTICE [sshd] Ban 203.0.113.50
    2024-11-10 13:34:56,789 fail2ban.actions [12345]: NOTICE [sshd] Unban 203.0.113.50
    """
```

### 2. Pipeline de dados

```
fail2ban.log → Bronze (raw) → Silver (parsed) → Gold (fail2ban_events)
```

Gold schema:
```
fail2ban_events/
  - timestamp
  - action (ban/unban)
  - jail (sshd, etc.)
  - source_ip
  - detection_date (partition)
```

### 3. Função para bans ativos

```python
def get_active_bans(fail2ban_df: pd.DataFrame) -> set[str]:
    """Return set of IPs currently banned.
    
    An IP is actively banned if its last event was 'Ban' (not 'Unban').
    """
```

### 4. Dashboard integration

- Nova seção "IPs Banidos pelo fail2ban"
- Nos alertas, badge "🚫 Já banido" se IP está na lista de bans ativos
- Filtro para mostrar/ocultar IPs já banidos

### 5. Blocklist generator

```python
def generate_blocklist(alerts_df, fail2ban_df, min_severity="high"):
    active_bans = get_active_bans(fail2ban_df)

    # Filtra IPs que NÃO estão banidos
    new_threats = alerts_df[~alerts_df["source_ip"].isin(active_bans)]

    # Gera blocklist apenas com novos IPs
    ...
```

## Consequências

### Positivas
- Visibilidade de o que fail2ban já está fazendo
- Blocklist gerada é realmente útil (sem duplicatas)
- Não interfere com fail2ban existente
- Nunca aplica bans automaticamente (ADR-005)

### Negativas
- Dependência de formato do fail2ban.log
- Se fail2ban mudar formato, parser precisa atualizar

### Importante

O Attack Detector **nunca** executa fail2ban-client ou modifica regras.
Apenas lê logs e mostra informações. Bloqueios são sempre manuais.
