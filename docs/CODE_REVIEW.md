# Code Review — VPS Attack Detector

Data: 2024-11-10

## Eixo 1: Standards (CODING_STANDARDS.md)

### Conformidade

| Item | Status | Notas |
|------|--------|-------|
| Python 3.11+ | ✅ | Dockerfile usa 3.11 |
| Nomenclatura snake_case | ✅ | Funções e variáveis consistentes |
| Type hints em interfaces | ✅ | Parsers, detectores, GeoIP tipados |
| Docstrings Google style | ✅ | Funções públicas documentadas |
| Sem hardcoded credentials | ✅ | Tudo via env vars |
| Testes em tests/ | ✅ | 42 testes cobrindo seams acordados |
| Commits com ticket ID | ✅ | [002], [003,004,007], etc |

### Code Smells (Fowler baseline)

| Smell | Encontrado? | Ação |
|-------|------------|------|
| Mysterious Name | ❌ | Nomes seguem GLOSSARY.md |
| Duplicated Code | ⚠️ Menor | Padrões de UDF repetidos em silver_transform, aceitável |
| Feature Envy | ❌ | Módulos bem encapsulados |
| Data Clumps | ❌ | Alert schema é consistente |
| Primitive Obsession | ❌ | Severity e alert_type como strings, aceitável para Parquet |
| Speculative Generality | ❌ | Nenhuma abstração não utilizada |

### Resultado Standards: ✅ PASS

Código segue os padrões documentados. Smell menor de duplicação em UDFs é aceitável dado o isolamento.

---

## Eixo 2: Spec (docs/SPEC.md)

### User Stories

| # | Story | Implementado? | Evidência |
|---|-------|---------------|-----------|
| 1 | Ver top IPs atacantes | ✅ | Dashboard: Top 10 IPs |
| 2 | Alerta success after failure | ✅ | Detectado: severity=critical |
| 3 | Ver países dos ataques | ✅ | Dashboard + GeoIP enrichment |
| 4 | Timeline de ataques | ✅ | Dashboard: gráfico temporal |
| 5 | Thresholds configuráveis | ✅ | config/detection_rules.yaml |
| 6 | Rodar sem intervenção | ✅ | DAG @hourly |
| 7 | Demo com dados exemplo | ✅ | data/sample_logs/ + pipeline testado |
| 8 | Degradação sem GeoIP | ✅ | Retorna "Unknown" sem DB |
| 9 | Blocklist sugerida manual | ✅ | scripts/generate_blocklist.py |
| 10 | Poucos recursos | ✅ | Configuração de memória documentada |
| 11 | Backfill sem duplicar | ✅ | Particionamento por data |
| 12 | Cross-reference threat feeds | ✅ | DAG refresh_threat_feeds |
| 13 | Docs em português | ✅ | README.md em pt-BR |
| 14 | Sync remoto SSH | ✅ | Suporte em DAG + scripts |
| 15 | Detectar path scanning | ✅ | detect_path_scanning() |
| 16 | Detectar scanner UAs | ✅ | detect_scanner_ua() |
| 17 | Relatório diário | ✅ | DAG daily_report |

### Seams de Teste Acordados

| Seam | Testado? | Cobertura |
|------|----------|-----------|
| Parsers | ✅ | 23 testes |
| Detectors | ✅ | 11 testes |
| GeoIP | ✅ | 8 testes |

### Out of Scope Respeitado

| Item | Violado? |
|------|----------|
| Bloqueio automático | ❌ Não implementado (correto) |
| Análise de payload HTTP | ❌ Não implementado (correto) |
| Machine Learning | ❌ Não implementado (correto) |
| Multi-tenancy | ❌ Não implementado (correto) |

### Resultado Spec: ✅ PASS

Todas as 17 user stories implementadas. Seams testados conforme acordado. Out of scope respeitado.

---

## Sumário

| Eixo | Resultado |
|------|-----------|
| Standards | ✅ PASS |
| Spec | ✅ PASS |

### Descobertas Menores (não bloqueantes)

1. **Documentação inline**: Alguns comentários poderiam ser mais concisos
2. **Cache do dashboard**: Poderia ter TTL configurável via env var
3. **Rate spike detection**: Poderia ter threshold dinâmico baseado em baseline

### Próximos Passos Recomendados (fora do escopo atual)

1. Teste de integração Docker Compose end-to-end
2. Webhook para alertas críticos
3. Retenção automática de dados antigos
