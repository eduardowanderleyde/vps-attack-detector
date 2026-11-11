#!/bin/bash
# VPS Attack Detector - Production Deployment Script
#
# This script performs initial deployment to a VPS.
# Run with: sudo ./scripts/deploy.sh
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - User in docker group
#   - Git repository cloned

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

cd "$PROJECT_DIR"

# ==============================================================================
# Pre-flight checks
# ==============================================================================

info "Running pre-flight checks..."

if ! command -v docker &> /dev/null; then
    error "Docker is not installed"
fi

if ! command -v docker compose &> /dev/null; then
    error "Docker Compose is not installed"
fi

if ! docker info &> /dev/null; then
    error "Docker daemon is not running or current user cannot access it"
fi

if [ ! -f docker-compose.yml ]; then
    error "docker-compose.yml not found. Are you in the project directory?"
fi

if [ ! -f docker-compose.prod.yml ]; then
    error "docker-compose.prod.yml not found"
fi

info "✓ Pre-flight checks passed"

# ==============================================================================
# Environment setup
# ==============================================================================

if [ ! -f .env ]; then
    info "Creating .env from template..."
    cp .env.example .env
    
    info "Generating secure passwords..."
    POSTGRES_PASSWORD=$(openssl rand -base64 24)
    AIRFLOW_PASSWORD=$(openssl rand -base64 24)
    AIRFLOW_SECRET=$(openssl rand -base64 32)
    FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32)
    
    sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
    sed -i "s/AIRFLOW_ADMIN_PASSWORD=.*/AIRFLOW_ADMIN_PASSWORD=$AIRFLOW_PASSWORD/" .env
    sed -i "s/AIRFLOW_SECRET_KEY=.*/AIRFLOW_SECRET_KEY=$AIRFLOW_SECRET/" .env
    sed -i "s/AIRFLOW_FERNET_KEY=.*/AIRFLOW_FERNET_KEY=$FERNET_KEY/" .env
    sed -i "s/^AIRFLOW_UID=.*/AIRFLOW_UID=$(id -u)/" .env
    
    chmod 600 .env
    info "✓ .env created with secure passwords"
    
    echo ""
    echo "=================================================="
    echo "IMPORTANT: Save these credentials securely!"
    echo "=================================================="
    echo "Airflow admin password: $AIRFLOW_PASSWORD"
    echo "PostgreSQL password: $POSTGRES_PASSWORD"
    echo "=================================================="
    echo ""
else
    info "✓ .env already exists"
fi

# ==============================================================================
# Create directories
# ==============================================================================

info "Creating data directories..."
mkdir -p data/bronze data/silver data/gold
mkdir -p data/geoip data/output data/checkpoints
chmod 755 data

info "✓ Directories created"

# ==============================================================================
# Check log access
# ==============================================================================

info "Checking log file access..."

if [ -f /var/log/auth.log ]; then
    if [ -r /var/log/auth.log ]; then
        info "✓ /var/log/auth.log is readable"
    else
        warn "/var/log/auth.log is not readable by current user"
        warn "Consider: sudo usermod -aG adm $USER"
    fi
fi

if [ -f /var/log/fail2ban.log ]; then
    if [ -r /var/log/fail2ban.log ]; then
        info "✓ /var/log/fail2ban.log is readable"
    else
        warn "/var/log/fail2ban.log is not readable"
    fi
fi

# ==============================================================================
# Check ports
# ==============================================================================

info "Checking port availability..."

check_port() {
    if ss -tlnp 2>/dev/null | grep -q ":$1 "; then
        warn "Port $1 is in use - adjust in .env if needed"
        return 1
    fi
    return 0
}

check_port 8085 && info "✓ Port 8085 (Airflow) is free"
check_port 8501 && info "✓ Port 8501 (Dashboard) is free"

# ==============================================================================
# Download GeoIP database (optional)
# ==============================================================================

if [ ! -f data/geoip/dbip-city-lite.mmdb ]; then
    info "Downloading GeoIP database..."
    MONTH=$(date +%Y-%m)
    curl -sL "https://download.db-ip.com/free/dbip-city-lite-$MONTH.mmdb.gz" | gunzip > data/geoip/dbip-city-lite.mmdb 2>/dev/null && \
        info "✓ GeoIP database downloaded" || \
        warn "GeoIP download failed (will work without it)"
else
    info "✓ GeoIP database exists"
fi

# ==============================================================================
# Build and start
# ==============================================================================

info "Building Docker images..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml build

info "Starting production stack..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

info "Waiting for services to be healthy..."
sleep 10

docker compose -f docker-compose.yml -f docker-compose.prod.yml ps

echo ""
info "=================================================="
info "Deployment complete!"
info "=================================================="
info ""
info "Airflow UI:  http://127.0.0.1:8085"
info "Dashboard:   http://127.0.0.1:8501"
info ""
info "To view logs: make prod-logs"
info "To stop:      make prod-down"
info "=================================================="
