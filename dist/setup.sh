#!/usr/bin/env bash
# =============================================================================
# AXCerberus WAF — Setup Script v2.0.0
#
# Called by PluginManager AFTER standard lifecycle completes:
#   - Directories created (from manifest lifecycle.directories)
#   - Binary installed (architecture-detected)
#   - Service user created (from manifest lifecycle.systemd.user)
#   - Hooks + config.avx copied
#   - Rules/assets deployed automatically
#   - Touch-files created for config-referenced paths (.avx, .log)
#   - Directory ownership set for service user
#   - Systemd service generated + enabled
#
# This script handles WAF-specific setup:
#   1. Download GeoIP database
#   2. Detect & shift web server port 80 → backend
#   3. Create per-site proxy configs (443 → WAF → backend)
#   4. Create backend server blocks for each site
#   5. Update WAF config upstream to match shifted port
# =============================================================================

set -euo pipefail

readonly SLUG="axcerberus"
readonly CONF_DIR="/etc/aevonx/plugins/${SLUG}"
readonly CONFIG_FILE="${CONF_DIR}/config.avx"
readonly FALLBACK_PORT=8181
readonly WAF_PORT_DEFAULT=8080
readonly BACKENDS_CONF="/etc/nginx/sites-available/axcerberus-backends.conf"
readonly SETUP_MARKER="${CONF_DIR}/.setup-done"

# Helpers
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; RED=''; NC=''
fi
log_info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_err()  { echo -e "${RED}[ERR]${NC}   $*" >&2; }

port_in_use() { ss -tlnp 2>/dev/null | grep -q ":$1 " || netstat -tlnp 2>/dev/null | grep -q ":$1 "; }
find_free_port() { local p="$1"; while port_in_use "${p}"; do p=$((p+1)); done; echo "${p}"; }

# ---------------------------------------------------------------------------
# 0 — Find available WAF port (localhost only)
# ---------------------------------------------------------------------------
WAF_PORT="${WAF_PORT_DEFAULT}"
if port_in_use "${WAF_PORT}"; then
    # Check if it's already our process
    if ! ss -tlnp 2>/dev/null | grep ":${WAF_PORT} " | grep -q "axcerberus"; then
        WAF_PORT=$(find_free_port "${WAF_PORT_DEFAULT}")
        log_warn "Port ${WAF_PORT_DEFAULT} in use, using ${WAF_PORT} for WAF"
    fi
fi

# Update WAF listen to localhost only (security: prevent direct external access)
if command -v python3 &>/dev/null && [ -f "${CONFIG_FILE}" ]; then
    python3 -c "
import json
with open('${CONFIG_FILE}') as f: data = json.load(f)
for sec in data.get('config_schema', []):
    for field in sec.get('fields', []):
        if field.get('key') == 'listen':
            field['value'] = '127.0.0.1:${WAF_PORT}'
with open('${CONFIG_FILE}', 'w') as f: json.dump(data, f, indent=4)
" 2>/dev/null && log_ok "WAF listen → 127.0.0.1:${WAF_PORT} (localhost only)"
fi

# ---------------------------------------------------------------------------
# 1 — Detect web server & determine backend port
# (GeoIP auto-downloaded by axcerberus binary on first start)
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
                # Save ALL site configs (originals for uninstall)
                for f in /etc/nginx/sites-available/*; do
                    [ -f "$f" ] && cp "$f" "${CONF_DIR}/nginx-originals/$(basename "$f").orig" 2>/dev/null || true
                done
                # Shift port 80 → backend in default/fallback configs
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
                # Disable certbot HTTP→HTTPS redirects (WAF handles routing)
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
                LSWS_CONF="/usr/local/lsws/conf/httpd_config.conf"
                LSWS_XML="/usr/local/lsws/conf/httpd_config.xml"
                cp -a /usr/local/lsws/conf "/tmp/axcerberus-lsws-backup-$(date +%s)" 2>/dev/null || true
                if [ -f "${LSWS_XML}" ]; then
                    sed -i "s|<address>\*:80</address>|<address>*:${WS_PORT}</address>|g" "${LSWS_XML}"
                    sed -i "s|<address>0\.0\.0\.0:80</address>|<address>0.0.0.0:${WS_PORT}</address>|g" "${LSWS_XML}"
                elif [ -f "${LSWS_CONF}" ]; then
                    sed -i "s/address[[:space:]]*\*:80/address *:${WS_PORT}/g" "${LSWS_CONF}"
                    sed -i "s/address[[:space:]]*0\.0\.0\.0:80/address 0.0.0.0:${WS_PORT}/g" "${LSWS_CONF}"
                fi
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
# 2 — Nginx: create per-site SSL proxy → WAF → backend
# ---------------------------------------------------------------------------
if [ "${WS}" = "nginx" ] && [ "${WS_PORT}" -gt 0 ] 2>/dev/null; then
    SITES_CHANGED=false

    for site_conf in /etc/nginx/sites-available/*; do
        [ -f "${site_conf}" ] || continue
        site_name=$(basename "${site_conf}")
        # Skip default, backends conf, and already-proxied configs
        [ "${site_name}" = "default" ] && continue
        [[ "${site_name}" == axcerberus-* ]] && continue
        [[ "${site_name}" == *.pre-waf ]] && continue
        [[ "${site_name}" == *.orig ]] && continue

        # Check if this site has SSL (listen 443 ssl)
        if ! grep -q 'listen.*443.*ssl' "${site_conf}" 2>/dev/null; then
            continue
        fi

        # Check if already proxied to WAF
        if grep -q "proxy_pass.*127.0.0.1:${WAF_PORT}" "${site_conf}" 2>/dev/null; then
            log_info "${site_name}: already proxied through WAF"
            continue
        fi

        # Save original if not already saved
        if [ ! -f "${CONF_DIR}/nginx-originals/${site_name}.orig" ]; then
            mkdir -p "${CONF_DIR}/nginx-originals"
            cp "${site_conf}" "${CONF_DIR}/nginx-originals/${site_name}.orig"
        fi

        # Extract domain name from server_name directive
        DOMAIN=$(grep -oP 'server_name\s+\K[^;]+' "${site_conf}" | head -1 | awk '{print $1}')
        [ -z "${DOMAIN}" ] && continue

        # Extract SSL cert paths
        SSL_CERT=$(grep -oP 'ssl_certificate\s+\K[^;]+' "${site_conf}" | head -1)
        SSL_KEY=$(grep -oP 'ssl_certificate_key\s+\K[^;]+' "${site_conf}" | head -1)

        [ -z "${SSL_CERT}" ] || [ -z "${SSL_KEY}" ] && continue

        # Extract optional SSL includes
        SSL_INCLUDE=$(grep 'include.*letsencrypt.*options' "${site_conf}" | head -1 || true)
        SSL_DHPARAM=$(grep 'ssl_dhparam' "${site_conf}" | head -1 || true)

        # Extract all location blocks and PHP config for backend
        ROOT_DIR=$(grep -oP '^\s*root\s+\K[^;]+' "${site_conf}" | head -1)
        [ -z "${ROOT_DIR}" ] && ROOT_DIR="/var/www/${DOMAIN}"

        # Build frontend proxy config (SSL → WAF)
        {
            echo "# AXCerberus WAF Frontend — auto-generated by setup.sh"
            echo "# Original saved at: ${CONF_DIR}/nginx-originals/${site_name}.orig"
            echo "server {"
            echo "    server_name ${DOMAIN};"
            echo "    listen 443 ssl;"
            echo "    ssl_certificate ${SSL_CERT};"
            echo "    ssl_certificate_key ${SSL_KEY};"
            [ -n "${SSL_INCLUDE}" ] && echo "    ${SSL_INCLUDE}"
            [ -n "${SSL_DHPARAM}" ] && echo "    ${SSL_DHPARAM}"
            echo ""
            echo "    location / {"
            echo "        proxy_pass http://127.0.0.1:${WAF_PORT};"
            echo "        proxy_set_header Host \$host;"
            echo "        proxy_set_header X-Real-IP \$remote_addr;"
            echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
            echo "        proxy_set_header X-Forwarded-Proto https;"
            echo "        proxy_http_version 1.1;"
            echo "        proxy_set_header Connection \"\";"
            echo "        proxy_connect_timeout 10s;"
            echo "        proxy_read_timeout 60s;"
            echo "        proxy_send_timeout 60s;"
            echo "    }"
            echo "}"
            echo "server {"
            echo "    listen 80;"
            echo "    server_name ${DOMAIN};"
            echo "    return 301 https://\$host\$request_uri;"
            echo "}"
        } > "${site_conf}"

        # Add backend server block
        {
            echo ""
            echo "# Backend for ${DOMAIN} — auto-generated by setup.sh"
            echo "server {"
            echo "    listen ${WS_PORT};"
            echo "    server_name ${DOMAIN};"
            echo "    root ${ROOT_DIR};"
            echo "    index index.php index.html;"
            # Copy PHP and other location blocks from original
            if grep -q 'fastcgi_pass' "${CONF_DIR}/nginx-originals/${site_name}.orig" 2>/dev/null; then
                echo "    location / { try_files \$uri \$uri/ =404; }"
                # Extract PHP socket/port from original
                PHP_SOCK=$(grep -oP 'fastcgi_pass\s+\K[^;]+' "${CONF_DIR}/nginx-originals/${site_name}.orig" | head -1)
                echo "    location ~ \\.php\$ {"
                echo "        fastcgi_pass ${PHP_SOCK};"
                echo "        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;"
                echo "        include fastcgi_params;"
                echo "        fastcgi_buffer_size 64k;"
                echo "        fastcgi_buffers 16 64k;"
                echo "        fastcgi_busy_buffers_size 128k;"
                echo "    }"
            else
                echo "    location / { try_files \$uri \$uri/ =404; }"
            fi
            # Include error pages if original had them
            if grep -q 'snippets/aevonx-errors.conf' "${CONF_DIR}/nginx-originals/${site_name}.orig" 2>/dev/null; then
                echo "    include snippets/aevonx-errors.conf;"
            fi
            echo "    location ~ /\\.(?!well-known).* { deny all; }"
            echo "}"
        } >> "${BACKENDS_CONF}" 2>/dev/null || {
            # Create backends file if first site
            {
                echo "# AXCerberus WAF Backends — auto-generated by setup.sh"
                echo "# Traffic flow: Client → Nginx:443 (SSL) → WAF:${WAF_PORT} → Nginx:${WS_PORT} (here)"
            } > "${BACKENDS_CONF}"
            # Retry append
            {
                echo ""
                echo "server {"
                echo "    listen ${WS_PORT};"
                echo "    server_name ${DOMAIN};"
                echo "    root ${ROOT_DIR};"
                echo "    index index.php index.html;"
                echo "    location / { try_files \$uri \$uri/ =404; }"
                echo "    location ~ /\\.(?!well-known).* { deny all; }"
                echo "}"
            } >> "${BACKENDS_CONF}"
        }

        SITES_CHANGED=true
        log_ok "${DOMAIN}: SSL proxy → WAF:${WAF_PORT} → backend:${WS_PORT}"
    done

    # Initialize backends file header if it doesn't exist yet
    if [ ! -f "${BACKENDS_CONF}" ]; then
        echo "# AXCerberus WAF Backends — auto-generated by setup.sh" > "${BACKENDS_CONF}"
    fi

    # Enable backends config
    ln -sf "${BACKENDS_CONF}" /etc/nginx/sites-enabled/axcerberus-backends.conf 2>/dev/null || true

    if [ "${SITES_CHANGED}" = true ]; then
        if nginx -t 2>/dev/null; then
            systemctl reload nginx
            log_ok "Nginx reloaded with WAF proxy configs"
        else
            log_err "Nginx config test FAILED — rolling back site configs"
            # Rollback: restore originals
            for orig in "${CONF_DIR}/nginx-originals"/*.orig; do
                [ -f "${orig}" ] || continue
                dest="/etc/nginx/sites-available/$(basename "${orig}" .orig)"
                cp "${orig}" "${dest}"
            done
            rm -f "${BACKENDS_CONF}" /etc/nginx/sites-enabled/axcerberus-backends.conf
            nginx -t 2>/dev/null && systemctl reload nginx
            log_err "Rolled back to original configs"
            exit 1
        fi
    fi

    # Add localhost and server IP to WAF allowlist
    if command -v /usr/local/bin/axcerberus &>/dev/null; then
        /usr/local/bin/axcerberus exec waf.allowlist.add 127.0.0.1 >/dev/null 2>&1 || true
        SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -n "${SERVER_IP}" ] && /usr/local/bin/axcerberus exec waf.allowlist.add "${SERVER_IP}" >/dev/null 2>&1 || true
    fi
fi

# ---------------------------------------------------------------------------
# 3 — Update WAF config upstream
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

# Save setup marker with metadata for uninstall
echo "{\"ws\":\"${WS}\",\"ws_port\":${WS_PORT:-0},\"waf_port\":${WAF_PORT},\"setup_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "${SETUP_MARKER}"

log_ok "AXCerberus WAF setup complete"
[ -n "${WS}" ] && log_info "Upstream: ${WS} on port ${WS_PORT}"
log_info "Flow: Client → Nginx:443 (SSL) → WAF:${WAF_PORT} → ${WS}:${WS_PORT}"
