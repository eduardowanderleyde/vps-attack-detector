# ADR-005: Não Aplicar Bloqueios Automaticamente

## Status
Aceito

## Contexto
O sistema detecta IPs atacantes e poderia, em teoria, aplicar bloqueios automaticamente via fail2ban ou ufw. Isso é comum em sistemas de IDS/IPS.

**Fatos:**
- VPS hospeda serviços de produção do dono
- Falsos positivos podem bloquear usuários legítimos ou o próprio dono
- SSH é a única forma de acesso ao VPS (não há console OOB)
- Dono pode não estar disponível 24/7 para desbloquear

## Decisão
**Nunca aplicar bloqueios automaticamente.** O sistema apenas:

1. Detecta e registra alertas
2. Gera arquivo de blocklist como sugestão
3. Mostra no dashboard para decisão humana

O dono deve revisar a blocklist e aplicar manualmente se desejar:
```bash
# Exemplo: adicionar ao fail2ban
sudo fail2ban-client set sshd banip <IP>

# Exemplo: adicionar ao ufw
sudo ufw deny from <IP>
```

## Alternativas Consideradas

### Auto-block com whitelist
- **Prós:** Proteção automatizada; whitelist evita auto-lock
- **Contras:** Whitelist pode estar incompleta; IPs dinâmicos; risco alto

### Auto-block temporário (1h)
- **Prós:** Mitiga ataques ativos; desbloqueio automático
- **Contras:** Ainda pode bloquear usuário legítimo por 1h; dono pode perder acesso

### Auto-block com confirmação via Telegram/Slack
- **Prós:** Humano no loop; resposta rápida
- **Contras:** Adiciona dependência de serviço externo; complexidade

### Fail2ban nativo (sem este sistema)
- **Prós:** Já faz auto-block com thresholds
- **Contras:** Não correlaciona múltiplas fontes; sem dashboard; menos visibilidade

## Consequências

### Positivas
- Zero risco de auto-lockout
- Dono mantém controle total
- Falsos positivos são inofensivos (só geram alerta)
- Sistema é observabilidade, não enforcement

### Negativas
- Ataques continuam até intervenção manual
- Requer que dono monitore dashboard/alertas
- Não mitiga ataques em tempo real

### Mitigações
- Documentar claramente que sistema é de detecção, não prevenção
- Sugerir uso complementar de fail2ban para proteção automática de SSH
- Opcional: integrar webhook para alertas críticos
