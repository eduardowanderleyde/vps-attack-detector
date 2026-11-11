# 012: Gerador de Blocklist

**O que construir:** Script que lê alertas de alta severidade e gera arquivo de texto com IPs únicos para uso manual com fail2ban/ufw.

**Blocked by:** 008 (Gold alerts)

**Status:** ready-for-agent

- [ ] `scripts/generate_blocklist.py` executável
- [ ] Argumentos: --alerts-path, --output-path, --min-severity (default: high)
- [ ] Lê Parquet de alertas
- [ ] Filtra por severidade mínima
- [ ] Extrai IPs únicos
- [ ] Ordena por número de alertas (mais perigoso primeiro)
- [ ] Grava arquivo texto, um IP por linha
- [ ] Comentário no topo: data de geração, total de IPs, aviso de revisão manual
- [ ] Documentação de como usar com fail2ban/ufw
