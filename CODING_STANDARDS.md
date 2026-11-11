# Padrões de Código — VPS Attack Detector

Este documento define os padrões de código do projeto. O code review usa estes padrões como referência.

## Linguagem e Estilo

### Python
- **Versão:** Python 3.11+
- **Formatação:** Black (linha máxima 88 caracteres)
- **Imports:** isort (seções: stdlib, third-party, local)
- **Linting:** Ruff para lint rápido
- **Type hints:** Obrigatórios em interfaces públicas de módulos

### Nomenclatura
- **Funções e variáveis:** `snake_case`
- **Classes:** `PascalCase`
- **Constantes:** `UPPER_SNAKE_CASE`
- **Arquivos:** `snake_case.py`
- **Vocabulário:** Usar termos do GLOSSARY.md consistentemente

### Docstrings
- Google style para funções públicas
- Incluir Args, Returns, Raises quando aplicável
- Exemplo mínimo quando o uso não for óbvio

```python
def parse_auth_log(line: str) -> dict[str, Any] | None:
    """Parse uma linha de auth.log para campos estruturados.
    
    Args:
        line: Linha raw do auth.log (ex: "Nov 10 12:34:56 host sshd[123]: ...")
    
    Returns:
        Dict com campos extraídos ou None se linha não reconhecida.
        Campos: timestamp, host, service, pid, message, event_type
    
    Example:
        >>> parse_auth_log("Nov 10 12:34:56 myhost sshd[1234]: Failed password for root")
        {'timestamp': ..., 'event_type': 'failed_password', ...}
    """
```

## Estrutura de Código

### Módulos Spark
- Um job por arquivo em `spark/jobs/`
- Funções utilitárias em `spark/jobs/utils/`
- Configuração via argumentos CLI ou env vars, nunca hardcoded
- Usar SparkSession.builder com configuração explícita

```python
def create_spark_session(app_name: str) -> SparkSession:
    return (
        SparkSession.builder.appName(app_name)
        .config("spark.sql.parquet.compression.codec", "snappy")
        .getOrCreate()
    )
```

### DAGs Airflow
- Um DAG por arquivo em `airflow/dags/`
- DAG ID = nome do arquivo sem extensão
- Usar `@dag` e `@task` decorators (TaskFlow API)
- Configuração de schedule via env vars quando possível
- Sempre definir `catchup=False` a menos que backfill seja intencional

```python
@dag(
    dag_id="ingest_and_detect",
    schedule="@hourly",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=["attack-detector"],
)
def ingest_and_detect(): ...
```

### Dashboard Streamlit
- Código principal em `dashboard/app.py`
- Componentes reutilizáveis em funções separadas
- Usar `@st.cache_data` para leituras de arquivo
- Configuração via env vars ou sidebar

## Tratamento de Erros

### Parsers
- Retornar `None` para linhas não reconhecidas (não raise)
- Logar warnings para linhas malformadas inesperadas
- Nunca falhar silenciosamente: ou parseia ou indica que não parseou

### Jobs Spark
- Usar try/except no nível do job, não em cada linha
- Propagar exceções para Airflow lidar com retry
- Logar contexto suficiente para debug

### Airflow Tasks
- Configurar retries para falhas transitórias (rede, etc)
- Usar `on_failure_callback` para alertas se configurado
- Tasks idempotentes: re-run não deve causar efeito duplicado

## Configuração

### Variáveis de Ambiente
- Todas as configs externas via env vars
- Defaults sensatos para desenvolvimento local
- Nunca commitar valores reais de produção

```python
import os

DATA_PATH = os.getenv("DATA_PATH", "/opt/airflow/data")
SSH_THRESHOLD = int(os.getenv("SSH_FAILED_THRESHOLD", "5"))
```

### Arquivos YAML
- `config/detection_rules.yaml` para thresholds de detecção
- Schema documentado com comentários
- Validar schema no startup

## Testes

### Estrutura
- Testes em `tests/` espelhando estrutura de `spark/jobs/`
- Um arquivo de teste por módulo testado
- Fixtures em `conftest.py`

### Nomenclatura
```python
def test_parse_auth_log_extracts_failed_password():
    """Nome descreve o comportamento testado."""


def test_detect_brute_force_returns_alert_above_threshold():
    """Não 'test_function_x' genérico."""
```

### Fixtures
- Usar pytest fixtures para dados de teste reutilizáveis
- Fixtures de DataFrame para testes de Spark
- Mocks para dependências externas (GeoIP DB, filesystem)

## Git

### Commits
- Mensagem em inglês, imperativo: "Add parser for nginx error logs"
- Prefixo com ID do ticket quando aplicável: "[001] Add parser for auth.log"
- Um commit por mudança lógica, não por arquivo

### Branches
- Feature branches: `feature/xxx-descricao`
- Bugfix branches: `fix/xxx-descricao`
- Sempre a partir de main atualizado

## Documentação

### README
- Em português brasileiro
- Inclui: o que é, como rodar, como configurar, como testar
- Diagrama de arquitetura (Mermaid)

### Código
- Comentários explicam "por quê", não "o quê"
- Evitar comentários óbvios: `# increment counter` antes de `counter += 1`
- Documentar decisões não-óbvias inline ou em ADR
