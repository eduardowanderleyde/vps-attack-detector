#!/bin/bash
# Download GeoIP database for VPS Attack Detector
#
# Supports:
#   - DB-IP Lite (free, no registration required)
#   - MaxMind GeoLite2 (requires license key)
#
# Usage:
#   ./scripts/download-geoip.sh                    # Download DB-IP Lite
#   ./scripts/download-geoip.sh --maxmind KEY      # Download MaxMind GeoLite2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GEOIP_DIR="${GEOIP_DIR:-$PROJECT_DIR/data/geoip}"
OUTPUT_FILE="$GEOIP_DIR/dbip-city-lite.mmdb"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --maxmind KEY    Use MaxMind GeoLite2 with license key"
    echo "  --output PATH    Output file path (default: $OUTPUT_FILE)"
    echo "  --help           Show this help"
    echo ""
    echo "Without options, downloads DB-IP Lite (free, no registration)."
}

download_dbip() {
    local month=$(date +%Y-%m)
    local url="https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz"
    local temp_file=$(mktemp)
    
    info "Downloading DB-IP City Lite database (${month})..."
    
    if ! curl -sL --fail "$url" -o "$temp_file.gz"; then
        rm -f "$temp_file.gz"
        error "Failed to download DB-IP database. Check your internet connection."
    fi
    
    info "Decompressing..."
    if ! gunzip -c "$temp_file.gz" > "$temp_file"; then
        rm -f "$temp_file.gz" "$temp_file"
        error "Failed to decompress database."
    fi
    rm -f "$temp_file.gz"
    
    # Verify file is valid MMDB
    if ! file "$temp_file" | grep -q "data"; then
        rm -f "$temp_file"
        error "Downloaded file does not appear to be a valid database."
    fi
    
    # Check minimum size (should be > 10MB)
    local size=$(stat -f%z "$temp_file" 2>/dev/null || stat -c%s "$temp_file")
    if [ "$size" -lt 10000000 ]; then
        warn "Database file is smaller than expected (${size} bytes)."
    fi
    
    mv "$temp_file" "$OUTPUT_FILE"
    info "✓ DB-IP City Lite database saved to: $OUTPUT_FILE"
    info "  Size: $(du -h "$OUTPUT_FILE" | cut -f1)"
}

download_maxmind() {
    local license_key="$1"
    local url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${license_key}&suffix=tar.gz"
    local temp_dir=$(mktemp -d)
    local temp_file="$temp_dir/geolite2.tar.gz"
    
    info "Downloading MaxMind GeoLite2-City database..."
    
    if ! curl -sL --fail "$url" -o "$temp_file"; then
        rm -rf "$temp_dir"
        error "Failed to download MaxMind database. Check your license key."
    fi
    
    info "Extracting..."
    if ! tar -xzf "$temp_file" -C "$temp_dir"; then
        rm -rf "$temp_dir"
        error "Failed to extract database."
    fi
    
    # Find the MMDB file
    local mmdb_file=$(find "$temp_dir" -name "*.mmdb" | head -1)
    if [ -z "$mmdb_file" ]; then
        rm -rf "$temp_dir"
        error "Could not find MMDB file in archive."
    fi
    
    mv "$mmdb_file" "$OUTPUT_FILE"
    rm -rf "$temp_dir"
    
    info "✓ MaxMind GeoLite2-City database saved to: $OUTPUT_FILE"
    info "  Size: $(du -h "$OUTPUT_FILE" | cut -f1)"
}

# Parse arguments
MAXMIND_KEY=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --maxmind)
            MAXMIND_KEY="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Create output directory
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Backup existing file
if [ -f "$OUTPUT_FILE" ]; then
    backup="$OUTPUT_FILE.bak.$(date +%Y%m%d)"
    info "Backing up existing database to: $backup"
    cp "$OUTPUT_FILE" "$backup"
fi

# Download
if [ -n "$MAXMIND_KEY" ]; then
    download_maxmind "$MAXMIND_KEY"
else
    download_dbip
fi

info "GeoIP database is ready for use."
