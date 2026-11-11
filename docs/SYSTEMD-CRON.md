# Alternativa: Execução com systemd/cron

Se preferir não usar Docker, o pipeline pode ser executado diretamente com systemd timers ou cron.

## Pré-requisitos

```bash
# Python 3.10+
sudo apt install python3 python3-pip python3-venv

# Java (para Spark)
sudo apt install openjdk-11-jre-headless

# PostgreSQL (para Airflow, opcional)
sudo apt install postgresql postgresql-contrib
```

## Instalação

### 1. Criar ambiente virtual

```bash
cd /opt/vps-attack-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Instalar Spark

```bash
wget https://archive.apache.org/dist/spark/spark-3.5.0/spark-3.5.0-bin-hadoop3.tgz
tar -xzf spark-3.5.0-bin-hadoop3.tgz
export SPARK_HOME=/opt/spark-3.5.0-bin-hadoop3
export PATH=$SPARK_HOME/bin:$PATH
```

### 3. Configurar variáveis de ambiente

Crie `/etc/vps-attack-detector.env`:

```bash
DATA_PATH=/opt/vps-attack-detector/data
GEOIP_DB_PATH=/opt/vps-attack-detector/data/geoip/dbip-city-lite.mmdb
TRUSTED_IP_CIDRS=177.x.x.x/32
DATA_RETENTION_DAYS=30
SPARK_HOME=/opt/spark-3.5.0-bin-hadoop3
```

## Opção 1: systemd Timers (Recomendado)

### Serviço de ingestão

Crie `/etc/systemd/system/attack-detector-ingest.service`:

```ini
[Unit]
Description=VPS Attack Detector - Log Ingestion
After=network.target

[Service]
Type=oneshot
User=www-data
Group=adm
EnvironmentFile=/etc/vps-attack-detector.env
WorkingDirectory=/opt/vps-attack-detector
ExecStart=/opt/vps-attack-detector/venv/bin/python -m spark.jobs.bronze_ingest
StandardOutput=journal
StandardError=journal
```

Crie `/etc/systemd/system/attack-detector-ingest.timer`:

```ini
[Unit]
Description=Run Attack Detector Ingestion every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

### Serviço de detecção

Crie `/etc/systemd/system/attack-detector-detect.service`:

```ini
[Unit]
Description=VPS Attack Detector - Detection
After=attack-detector-ingest.service

[Service]
Type=oneshot
User=www-data
Group=adm
EnvironmentFile=/etc/vps-attack-detector.env
WorkingDirectory=/opt/vps-attack-detector
ExecStart=/opt/vps-attack-detector/venv/bin/python -m spark.jobs.gold_detect
StandardOutput=journal
StandardError=journal
```

Crie `/etc/systemd/system/attack-detector-detect.timer`:

```ini
[Unit]
Description=Run Attack Detection every 15 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

### Serviço de retenção (diário)

Crie `/etc/systemd/system/attack-detector-prune.service`:

```ini
[Unit]
Description=VPS Attack Detector - Data Retention

[Service]
Type=oneshot
User=www-data
EnvironmentFile=/etc/vps-attack-detector.env
WorkingDirectory=/opt/vps-attack-detector
ExecStart=/opt/vps-attack-detector/venv/bin/python scripts/prune_old_data.py --audit-log /var/log/attack-detector-retention.log
StandardOutput=journal
StandardError=journal
```

Crie `/etc/systemd/system/attack-detector-prune.timer`:

```ini
[Unit]
Description=Run Data Retention daily at 3am

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

### Habilitar timers

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now attack-detector-ingest.timer
sudo systemctl enable --now attack-detector-detect.timer
sudo systemctl enable --now attack-detector-prune.timer
```

### Verificar status

```bash
systemctl list-timers attack-detector-*
journalctl -u attack-detector-ingest -f
```

## Opção 2: cron

Adicione ao crontab (`sudo crontab -e -u www-data`):

```cron
# VPS Attack Detector

# Variáveis de ambiente
DATA_PATH=/opt/vps-attack-detector/data
GEOIP_DB_PATH=/opt/vps-attack-detector/data/geoip/dbip-city-lite.mmdb
VENV=/opt/vps-attack-detector/venv/bin/python
WORKDIR=/opt/vps-attack-detector

# Ingestão a cada 5 minutos
*/5 * * * * cd $WORKDIR && $VENV -m spark.jobs.bronze_ingest >> /var/log/attack-detector-ingest.log 2>&1

# Detecção a cada 15 minutos
*/15 * * * * cd $WORKDIR && $VENV -m spark.jobs.gold_detect >> /var/log/attack-detector-detect.log 2>&1

# Retenção diária às 3am
0 3 * * * cd $WORKDIR && $VENV scripts/prune_old_data.py --audit-log /var/log/attack-detector-retention.log >> /var/log/attack-detector-prune.log 2>&1
```

## Dashboard (opcional)

Para executar o dashboard Streamlit como serviço:

Crie `/etc/systemd/system/attack-detector-dashboard.service`:

```ini
[Unit]
Description=VPS Attack Detector Dashboard
After=network.target

[Service]
Type=simple
User=www-data
EnvironmentFile=/etc/vps-attack-detector.env
WorkingDirectory=/opt/vps-attack-detector
ExecStart=/opt/vps-attack-detector/venv/bin/streamlit run dashboard/app.py --server.port 8501 --server.address 127.0.0.1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now attack-detector-dashboard
```

## Permissões

O usuário que executa os jobs precisa:

1. Acesso de leitura aos logs:
   ```bash
   sudo usermod -aG adm www-data
   ```

2. Permissão de escrita em `/opt/vps-attack-detector/data`:
   ```bash
   sudo chown -R www-data:www-data /opt/vps-attack-detector/data
   ```

## Monitoramento

### Logs

```bash
# systemd
journalctl -u attack-detector-ingest --since "1 hour ago"
journalctl -u attack-detector-detect --since "1 hour ago"

# cron
tail -f /var/log/attack-detector-*.log
```

### Alertas

Para receber alertas de falha, configure `OnFailure=` no serviço systemd:

```ini
[Unit]
OnFailure=notify-admin@%n.service
```

Ou use `MAILTO` no cron:

```cron
MAILTO=admin@example.com
```

## Comparação: Docker vs systemd/cron

| Aspecto | Docker | systemd/cron |
|---------|--------|--------------|
| Isolamento | Containers isolados | Processos compartilham sistema |
| Dependências | Empacotadas na imagem | Instaladas no sistema |
| Atualização | Rebuild da imagem | apt/pip upgrade |
| Recursos | Limites granulares | Limites via cgroups |
| Portabilidade | Alta | Dependente do sistema |
| Complexidade | Média | Baixa |

Para a maioria dos casos, Docker é recomendado pela facilidade de manutenção e reprodutibilidade.
