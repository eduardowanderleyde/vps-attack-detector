# ADR-010: Gerenciamento de Secrets

## Status
Aceito

## Contexto

O sistema requer credenciais (senhas de banco, Airflow admin) que não devem ser commitadas no repositório ou expostas em logs.

## Decisão

### 1. Secrets via .env (não commitado)

```bash
# .env (no servidor, chmod 600)
POSTGRES_PASSWORD=<senha-forte-gerada>
AIRFLOW_ADMIN_PASSWORD=<senha-forte-gerada>
AIRFLOW__CORE__FERNET_KEY=<chave-gerada>
```

### 2. .env.example com placeholders

```bash
# .env.example (commitado, sem valores reais)
POSTGRES_PASSWORD=CHANGE_ME_use_strong_password
AIRFLOW_ADMIN_PASSWORD=CHANGE_ME_use_strong_password
AIRFLOW__CORE__FERNET_KEY=CHANGE_ME_generate_with_python_cryptography
```

### 3. Nunca em docker-compose.yml

Errado:
```yaml
environment:
  POSTGRES_PASSWORD: minhasenha123  # NÃO FAZER
```

Correto:
```yaml
environment:
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  # Lê do .env
```

### 4. Geração de secrets

Documentar no DEPLOY.md:
```bash
# Gerar senha forte
openssl rand -base64 32

# Gerar Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 5. Permissões

```bash
chmod 600 .env
chown $USER:$USER .env
```

## Consequências

### Positivas
- Secrets nunca no git
- Fácil rotação (editar .env, restart)
- Padrão Docker Compose

### Negativas
- Arquivo .env em plaintext no disco
- Requer cuidado com backups

### Para ambientes mais seguros

Se necessário, usar Docker secrets ou Vault:
```yaml
secrets:
  postgres_password:
    file: ./secrets/postgres_password.txt
```

Mas para VPS single-user, .env é suficiente.
