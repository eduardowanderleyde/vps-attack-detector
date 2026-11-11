# 007: Regras de Detecção

**O que construir:** Módulo de detectores que analisam DataFrames Silver e identificam padrões de ataque, retornando DataFrames de alertas. Thresholds configuráveis via YAML.

**Blocked by:** 002 (entender estrutura dos dados parseados)

**Status:** ready-for-agent

- [ ] `config/detection_rules.yaml` com thresholds configuráveis:
  ```yaml
  ssh_brute_force:
    threshold: 5
    window_minutes: 10
  path_scanning:
    threshold: 20
    window_minutes: 5
    suspicious_paths: ["/wp-admin", "/.env", "/phpmyadmin", ...]
  scanner_user_agents:
    patterns: ["sqlmap", "nikto", "zgrab", "masscan", ...]
  rate_spike:
    threshold_per_minute: 100
  ```
- [ ] `spark/jobs/utils/detectors.py` com funções:
  - `detect_ssh_brute_force(df, config) -> alerts_df`
  - `detect_credential_stuffing(df, config) -> alerts_df`
  - `detect_path_scanning(df, config) -> alerts_df`
  - `detect_scanner_ua(df, config) -> alerts_df`
  - `detect_rate_spike(df, config) -> alerts_df`
  - `detect_success_after_failure(df, config) -> alerts_df`
- [ ] Cada detector retorna DataFrame com: `alert_id`, `alert_type`, `severity`, `source_ip`, `timestamp`, `evidence`
- [ ] Severidades: critical, high, medium, low
- [ ] `tests/test_detectors.py` com casos para cada detector:
  - Dados que devem gerar alerta
  - Dados abaixo do threshold (sem alerta)
- [ ] Todos os testes passando
