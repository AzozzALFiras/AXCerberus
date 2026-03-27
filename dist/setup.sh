#!/usr/bin/env bash
# =============================================================================
# AXCerberus WAF — Setup Script v1.0.0
#
# Called by PluginManager AFTER standard lifecycle completes:
#   - Directories created (from manifest lifecycle.directories)
#   - Binary installed (architecture-detected)
#   - Hooks + config.avx copied
#   - Systemd service generated + enabled
#
# This script only handles WAF-specific setup:
#   1. Create service user
#   2. Detect & shift web server port
#   3. Download GeoIP database
#   4. Update config upstream
# =============================================================================

set -euo pipefail

readonly SLUG="axcerberus"
readonly CONF_DIR="/etc/aevonx/plugins/${SLUG}"
readonly CONFIG_FILE="${CONF_DIR}/config.avx"
readonly LOG_DIR="/var/log/aevonx/plugins/${SLUG}"
readonly SERVICE_USER="aevonx-waf"
readonly FALLBACK_PORT=8181

# Helpers
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; NC=''
fi
log_info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }

port_in_use() { ss -tlnp 2>/dev/null | grep -q ":$1 " || netstat -tlnp 2>/dev/null | grep -q ":$1 "; }
find_free_port() { local p="$1"; while port_in_use "${p}"; do p=$((p+1)); done; echo "${p}"; }

# ---------------------------------------------------------------------------
# 1 — Service user
# ---------------------------------------------------------------------------
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin "${SERVICE_USER}" 2>/dev/null || true
fi
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}" 2>/dev/null || true
log_ok "Service user ready"

# ---------------------------------------------------------------------------
# 2 — GeoIP database
# ---------------------------------------------------------------------------
GEOIP="${CONF_DIR}/GeoLite2-Country.mmdb"
if [ ! -f "${GEOIP}" ]; then
    curl -sL "https://cdn.aevonx.com/geoip/GeoLite2-Country.mmdb" -o "${GEOIP}" 2>/dev/null || true
    [ -s "${GEOIP}" ] && log_ok "GeoIP downloaded" || { log_warn "GeoIP download failed"; rm -f "${GEOIP}"; }
fi

# ---------------------------------------------------------------------------
# 3 — Detect & shift web server
# ---------------------------------------------------------------------------
WS=""
if systemctl is-active --quiet nginx 2>/dev/null; then WS="nginx"
elif systemctl is-active --quiet apache2 2>/dev/null; then WS="apache2"
elif systemctl is-active --quiet httpd 2>/dev/null; then WS="httpd"
elif systemctl is-active --quiet lshttpd 2>/dev/null; then WS="lshttpd"
elif systemctl is-active --quiet lsws 2>/dev/null; then WS="lsws"
fi

WS_PORT=0
if [ -n "${WS}" ]; then
    # Check if already shifted
    shifted=$(ss -tlnp 2>/dev/null | grep "${WS}" | grep -oP '(?<=:)(818[0-9]|819[0-9]|82[0-9]{2})(?=\s)' | head -1 || true)
    if [ -n "${shifted}" ]; then
        WS_PORT="${shifted}"
        log_info "${WS} already on port ${shifted}"
    else
        WS_PORT=$(find_free_port "${FALLBACK_PORT}")
        log_info "Shifting ${WS} 80 → ${WS_PORT}"

        case "${WS}" in
            nginx)
                cp -a /etc/nginx "/tmp/axcerberus-nginx-backup-$(date +%s)"
                mkdir -p "${CONF_DIR}/nginx-originals"
                for f in /etc/nginx/sites-available/*; do
                    [ -f "$f" ] && cp "$f" "${CONF_DIR}/nginx-originals/$(basename "$f").orig" 2>/dev/null || true
                done
                for dir in /etc/nginx /etc/nginx/sites-available /etc/nginx/sites-enabled; do
                    [ -d "${dir}" ] || continue
                    find "${dir}" -type f \( -name "*.conf" -o ! -name "*.*" \) 2>/dev/null | while IFS= read -r f; do
                        sed -i \
                            -e "s/\(listen[[:space:]]*\)80\([[:space:]]*;\)/\1${WS_PORT}\2/g" \
                            -e "s/\(listen[[:space:]]*\)80\([[:space:]]*default_server\)/\1${WS_PORT}\2/g" \
                            -e "s/\(listen[[:space:]]*\[::\]:\)80\([[:space:]]*;\)/\1${WS_PORT}\2/g" \
                            -e "s/\(listen[[:space:]]*\[::\]:\)80\([[:space:]]*default_server\)/\1${WS_PORT}\2/g" \
                            "${f}"
                    done
                done
                for f in /etc/nginx/sites-available/*; do
                    [ -f "$f" ] && sed -i 's/\(.*return 301 https:\/\/.*\)/# \1  # disabled by axcerberus/' "$f" 2>/dev/null || true
                done
                nginx -t 2>/dev/null && systemctl restart nginx && log_ok "Nginx → port ${WS_PORT}"
                ;;
            apache2|httpd)
                [ -f /etc/apache2/ports.conf ] && sed -i "s/Listen 80\b/Listen ${WS_PORT}/g" /etc/apache2/ports.conf
                [ -f /etc/httpd/conf/httpd.conf ] && sed -i "s/Listen 80\b/Listen ${WS_PORT}/g" /etc/httpd/conf/httpd.conf
                systemctl reload "${WS}" 2>/dev/null || systemctl restart "${WS}" 2>/dev/null || true
                log_ok "${WS} → port ${WS_PORT}"
                ;;
            lshttpd|lsws)
                # LiteSpeed (OpenLiteSpeed + Enterprise) — listener config
                LSWS_CONF="/usr/local/lsws/conf/httpd_config.conf"
                LSWS_XML="/usr/local/lsws/conf/httpd_config.xml"
                cp -a /usr/local/lsws/conf "/tmp/axcerberus-lsws-backup-$(date +%s)" 2>/dev/null || true
                if [ -f "${LSWS_XML}" ]; then
                    # OpenLiteSpeed uses XML config
                    sed -i "s|<address>\*:80</address>|<address>*:${WS_PORT}</address>|g" "${LSWS_XML}"
                    sed -i "s|<address>0\.0\.0\.0:80</address>|<address>0.0.0.0:${WS_PORT}</address>|g" "${LSWS_XML}"
                elif [ -f "${LSWS_CONF}" ]; then
                    # LiteSpeed Enterprise uses conf format
                    sed -i "s/address[[:space:]]*\*:80/address *:${WS_PORT}/g" "${LSWS_CONF}"
                    sed -i "s/address[[:space:]]*0\.0\.0\.0:80/address 0.0.0.0:${WS_PORT}/g" "${LSWS_CONF}"
                fi
                # Also check per-listener configs in /usr/local/lsws/conf/listeners/
                if [ -d /usr/local/lsws/conf/listeners ]; then
                    find /usr/local/lsws/conf/listeners -type f 2>/dev/null | while IFS= read -r f; do
                        sed -i -e "s|<address>\*:80</address>|<address>*:${WS_PORT}</address>|g" \
                               -e "s/address[[:space:]]*\*:80/address *:${WS_PORT}/g" "${f}"
                    done
                fi
                systemctl restart "${WS}" 2>/dev/null || /usr/local/lsws/bin/lswsctrl restart 2>/dev/null || true
                log_ok "LiteSpeed → port ${WS_PORT}"
                ;;
        esac
    fi
fi

# ---------------------------------------------------------------------------
# 4 — Update config upstream
# ---------------------------------------------------------------------------
if [ "${WS_PORT}" -gt 0 ] 2>/dev/null && command -v python3 &>/dev/null; then
    python3 -c "
import json
with open('${CONFIG_FILE}') as f: data = json.load(f)
for sec in data.get('config_schema', []):
    for field in sec.get('fields', []):
        if field.get('key') == 'upstream':
            field['value'] = 'http://127.0.0.1:${WS_PORT}'
with open('${CONFIG_FILE}', 'w') as f: json.dump(data, f, indent=4)
" 2>/dev/null && log_ok "Upstream → 127.0.0.1:${WS_PORT}"
fi

# ---------------------------------------------------------------------------
# 5 — Deploy WAF rules
# ---------------------------------------------------------------------------
RULES_SRC_DIR="$(dirname "$(realpath "$0")")/rules"
RULES_DST_DIR="${CONF_DIR}/rules"
if [ -d "${RULES_SRC_DIR}" ] && [ "$(ls -1 "${RULES_SRC_DIR}"/*.conf 2>/dev/null | wc -l)" -gt 0 ]; then
    mkdir -p "${RULES_DST_DIR}"
    cp "${RULES_SRC_DIR}"/*.conf "${RULES_DST_DIR}/"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${RULES_DST_DIR}" 2>/dev/null || true
    log_ok "WAF rules deployed ($(ls -1 "${RULES_DST_DIR}"/*.conf | wc -l) files)"
else
    log_warn "No WAF rule files found in dist/rules/"
fi

# ---------------------------------------------------------------------------
# 6 — Create IP list files
# ---------------------------------------------------------------------------
touch "${CONF_DIR}/ip_allowlist.avx" "${CONF_DIR}/ip_blocklist.avx" 2>/dev/null || true

log_ok "AXCerberus WAF setup complete"
[ -n "${WS}" ] && log_info "Upstream: ${WS} on port ${WS_PORT}"
