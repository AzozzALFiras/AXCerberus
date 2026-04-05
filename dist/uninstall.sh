#!/usr/bin/env bash
# =============================================================================
# AXCerberus WAF — Uninstall Script v2.0.0
#
# Called by PluginManager BEFORE standard cleanup:
#   - PluginManager will stop/disable service, remove binary, dirs, hooks, config
#
# This script handles WAF-specific teardown:
#   1. Restore original nginx site configs (including SSL)
#   2. Remove WAF backend configs
#   3. Restore web server to port 80
#   4. Clean up WAF allowlist entries
# =============================================================================

set -euo pipefail

readonly SLUG="axcerberus"
readonly CONF_DIR="/etc/aevonx/plugins/${SLUG}"
readonly CONFIG_FILE="${CONF_DIR}/config.avx"
readonly NGINX_ORIGINALS="${CONF_DIR}/nginx-originals"
readonly BACKENDS_CONF="/etc/nginx/sites-available/axcerberus-backends.conf"
readonly SETUP_MARKER="${CONF_DIR}/.setup-done"

# Helpers
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; NC=''
fi
log_info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }

# ---------------------------------------------------------------------------
# 1 — Read setup metadata
# ---------------------------------------------------------------------------
PORT=""
if [ -f "${SETUP_MARKER}" ] && command -v python3 &>/dev/null; then
    PORT=$(python3 -c "
import json, sys
try:
    with open('${SETUP_MARKER}') as f: data = json.load(f)
    print(data.get('ws_port', ''))
except: pass
" 2>/dev/null || true)
fi

# Fallback: read from config file
if [ -z "${PORT}" ] && [ -f "${CONFIG_FILE}" ] && command -v python3 &>/dev/null; then
    PORT=$(python3 -c "
import json, re, sys
try:
    with open('${CONFIG_FILE}') as f: data = json.load(f)
    for sec in data.get('config_schema', []):
        for field in sec.get('fields', []):
            if field.get('key') == 'upstream':
                m = re.search(r':(\d+)\$', str(field.get('value','')))
                if m: print(m.group(1)); sys.exit(0)
except: pass
" 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# 2 — Detect web server
# ---------------------------------------------------------------------------
WS=""
if systemctl is-active --quiet nginx 2>/dev/null; then WS="nginx"
elif systemctl is-active --quiet apache2 2>/dev/null; then WS="apache2"
elif systemctl is-active --quiet httpd 2>/dev/null; then WS="httpd"
elif systemctl is-active --quiet lshttpd 2>/dev/null; then WS="lshttpd"
elif systemctl is-active --quiet lsws 2>/dev/null; then WS="lsws"
fi

# ---------------------------------------------------------------------------
# 3 — Nginx: Restore ALL original site configs
# ---------------------------------------------------------------------------
if [ "${WS}" = "nginx" ]; then
    RESTORED=0

    # Restore from saved originals (covers both HTTP and SSL proxy configs)
    if [ -d "${NGINX_ORIGINALS}" ]; then
        for orig in "${NGINX_ORIGINALS}"/*.orig; do
            [ -f "${orig}" ] || continue
            site_name=$(basename "${orig}" .orig)
            dest="/etc/nginx/sites-available/${site_name}"
            if [ -f "${dest}" ]; then
                cp "${orig}" "${dest}"
                RESTORED=$((RESTORED + 1))
                log_ok "Restored: ${site_name}"
            fi
        done
    fi

    # Remove WAF backend configs
    if [ -f "${BACKENDS_CONF}" ]; then
        rm -f "${BACKENDS_CONF}"
        rm -f "/etc/nginx/sites-enabled/axcerberus-backends.conf"
        log_ok "Removed WAF backend configs"
    fi

    # Remove any .pre-waf backup files (cleanup)
    for f in /etc/nginx/sites-available/*.pre-waf; do
        [ -f "$f" ] && rm -f "$f"
    done

    [ ${RESTORED} -gt 0 ] && log_ok "Restored ${RESTORED} site config(s) to original"
fi

# ---------------------------------------------------------------------------
# 4 — Restore web server to port 80
# ---------------------------------------------------------------------------
if [ -n "${WS}" ] && [ -n "${PORT}" ] && [ "${PORT}" != "80" ] && [ "${PORT}" != "0" ]; then
    log_info "Restoring ${WS} from port ${PORT} → 80"

    case "${WS}" in
        nginx)
            # Shift port back in ALL configs (default + sites)
            for dir in /etc/nginx /etc/nginx/sites-available /etc/nginx/sites-enabled; do
                [ -d "${dir}" ] || continue
                find "${dir}" -type f \( -name "*.conf" -o ! -name "*.*" \) 2>/dev/null | while IFS= read -r f; do
                    sed -i \
                        -e "s/\(listen[[:space:]]*\)${PORT}\([[:space:]]*;\)/\180\2/g" \
                        -e "s/\(listen[[:space:]]*\)${PORT}\([[:space:]]*default_server\)/\180\2/g" \
                        -e "s/\(listen[[:space:]]*\[::\]:\)${PORT}\([[:space:]]*;\)/\180\2/g" \
                        -e "s/\(listen[[:space:]]*\[::\]:\)${PORT}\([[:space:]]*default_server\)/\180\2/g" \
                        "${f}"
                done
            done
            # Restore certbot redirects
            for f in /etc/nginx/sites-available/*; do
                [ -f "$f" ] && sed -i 's/^# \(.*return 301 https:\/\/.*\)  # disabled by axcerberus/\1/' "$f" 2>/dev/null || true
            done
            if nginx -t 2>/dev/null; then
                systemctl restart nginx
                log_ok "Nginx restored to port 80"
            else
                log_warn "Nginx config test failed after restore — check manually!"
            fi
            ;;
        apache2|httpd)
            [ -f /etc/apache2/ports.conf ] && sed -i "s/Listen ${PORT}\b/Listen 80/g" /etc/apache2/ports.conf
            [ -f /etc/httpd/conf/httpd.conf ] && sed -i "s/Listen ${PORT}\b/Listen 80/g" /etc/httpd/conf/httpd.conf
            systemctl reload "${WS}" 2>/dev/null || systemctl restart "${WS}" 2>/dev/null || true
            log_ok "${WS} restored to port 80"
            ;;
        lshttpd|lsws)
            LSWS_CONF="/usr/local/lsws/conf/httpd_config.conf"
            LSWS_XML="/usr/local/lsws/conf/httpd_config.xml"
            if [ -f "${LSWS_XML}" ]; then
                sed -i "s|<address>\*:${PORT}</address>|<address>*:80</address>|g" "${LSWS_XML}"
                sed -i "s|<address>0\.0\.0\.0:${PORT}</address>|<address>0.0.0.0:80</address>|g" "${LSWS_XML}"
            elif [ -f "${LSWS_CONF}" ]; then
                sed -i "s/address[[:space:]]*\*:${PORT}/address *:80/g" "${LSWS_CONF}"
                sed -i "s/address[[:space:]]*0\.0\.0\.0:${PORT}/address 0.0.0.0:80/g" "${LSWS_CONF}"
            fi
            if [ -d /usr/local/lsws/conf/listeners ]; then
                find /usr/local/lsws/conf/listeners -type f 2>/dev/null | while IFS= read -r f; do
                    sed -i -e "s|<address>\*:${PORT}</address>|<address>*:80</address>|g" \
                           -e "s/address[[:space:]]*\*:${PORT}/address *:80/g" "${f}"
                done
            fi
            systemctl restart "${WS}" 2>/dev/null || /usr/local/lsws/bin/lswsctrl restart 2>/dev/null || true
            log_ok "LiteSpeed restored to port 80"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# 5 — Cleanup marker
# ---------------------------------------------------------------------------
rm -f "${SETUP_MARKER}" 2>/dev/null || true

log_ok "AXCerberus WAF teardown complete"
[ -n "${WS}" ] && log_info "${WS} restored to serve directly on port 80/443"
