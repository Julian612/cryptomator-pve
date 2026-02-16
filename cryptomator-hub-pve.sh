#!/usr/bin/env bash
# install-cryptomator-hub.sh
#
# Proxmox VE helper-artiges Install-Script für Cryptomator Hub in Debian 12 LXC (Docker Compose).
#
# Unterstützte Varianten:
#  A) "Internal Keycloak":  Postgres + Keycloak + Cryptomator Hub (alles im selben Compose-Stack)
#  B) "External Keycloak":  Postgres + Cryptomator Hub (Keycloak existiert bereits extern)
#
# Was das Script macht:
# - Fragt interaktiv alle relevanten Variablen ab (Defaults vorhanden)
# - Erstellt einen Debian 12 LXC (unprivileged, nesting=1, keyctl=1)
# - Installiert Docker + docker compose plugin im LXC
# - Schreibt /opt/cryptomator-hub/{compose.yml,.env,data/...} im LXC
# - Startet den Stack
# - Gibt am Ende eine Zusammenfassung aus
#
# Sicherheit:
# - Secrets werden in /opt/cryptomator-hub/.env im LXC abgelegt (chmod 600).
# - Checke .env und data/ nie ins Git ein.
#
# Reverse Proxy:
# - Standardmässig bindet das Script Ports nur auf 127.0.0.1 (für Reverse Proxy).
# - Keycloak (intern): 127.0.0.1:8081
# - Hub:               127.0.0.1:8082
#
# Lizenz: MIT (empfohlen für GitHub)

set -euo pipefail

### ---------------------------
### Helper functions
### ---------------------------
err() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Fehlendes Kommando: $1"; }

prompt() {
  # prompt "Label" "default" -> echo value
  local label="$1"
  local def="${2:-}"
  local val=""
  if [[ -n "$def" ]]; then
    read -r -p "$label [$def]: " val
    echo "${val:-$def}"
  else
    read -r -p "$label: " val
    echo "$val"
  fi
}

prompt_bool() {
  # prompt_bool "Label" "yes|no" -> echo yes/no
  local label="$1"
  local def="${2:-no}"
  local val=""
  read -r -p "$label (yes/no) [$def]: " val
  val="${val:-$def}"
  case "$val" in
    y|Y|yes|YES) echo "yes" ;;
    n|N|no|NO)   echo "no" ;;
    *) echo "$def" ;;
  esac
}

rand_hex() { local n="${1:-24}"; openssl rand -hex "$n"; }
rand_b64() { local n="${1:-24}"; openssl rand -base64 "$n" | tr -d '\n'; }

pct_exec() { local ctid="$1"; shift; pct exec "$ctid" -- bash -lc "$*"; }

pct_push_str() {
  local ctid="$1"
  local path="$2"
  local content="$3"
  local tmp
  tmp="$(mktemp)"
  printf "%s" "$content" >"$tmp"
  pct push "$ctid" "$tmp" "$path" --perms 0644
  rm -f "$tmp"
}

uuid_any() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    cat /proc/sys/kernel/random/uuid
  fi
}

### ---------------------------
### Preflight
### ---------------------------
need_cmd pveversion
need_cmd pct
need_cmd pveam
need_cmd openssl
need_cmd awk
need_cmd sed
need_cmd grep

[[ "$(id -u)" -eq 0 ]] || err "Bitte als root auf dem Proxmox VE Host ausführen."

info "Cryptomator Hub Installer (PVE helper-artig) – Internal/External Keycloak"

### ---------------------------
### Collect variables (interactive)
### ---------------------------

# Container basics
CTID="$(prompt "CTID (numerisch)" "120")"
[[ "$CTID" =~ ^[0-9]+$ ]] || err "CTID muss numerisch sein."

HOSTNAME="$(prompt "LXC Hostname" "cryptomator-hub")"
TZ="$(prompt "Zeitzone im LXC" "Europe/Zurich")"

# Variant selection
USE_EXTERNAL_KC="$(prompt_bool "Externen Keycloak verwenden (Keycloak nicht mitdeployen)?" "no")"

# Resources
CORES="$(prompt "CPU Cores" "2")"
RAM="$(prompt "RAM (MB)" "2048")"
DISK_GB="$(prompt "Disk (GB)" "16")"
SWAP_MB="$(prompt "Swap (MB)" "512")"

# Storage/network
STORAGE="$(prompt "Proxmox Storage für RootFS (z.B. local-lvm, local, zfs)" "local-lvm")"
BRIDGE="$(prompt "Network Bridge" "vmbr0")"
USE_DHCP="$(prompt_bool "Netzwerk via DHCP?" "yes")"

IP_CIDR=""
GATEWAY=""
DNS_SERVER=""
if [[ "$USE_DHCP" == "no" ]]; then
  IP_CIDR="$(prompt "Statische IP inkl. CIDR (z.B. 192.168.1.50/24)" "")"
  GATEWAY="$(prompt "Gateway (z.B. 192.168.1.1)" "")"
  DNS_SERVER="$(prompt "DNS Server (z.B. 1.1.1.1)" "1.1.1.1")"
fi

# Public URLs (für Redirects/Issuer/Proxy-Konfig)
HUB_PUBLIC_BASE="$(prompt "Hub Public Base URL (z.B. https://hub.example.tld)" "https://hub.example.tld")"
KC_PUBLIC_BASE="$(prompt "Keycloak Public Base URL (z.B. https://auth.example.tld oder https://example.tld/kc)" "https://auth.example.tld")"

# Host-local bindings
KC_BIND_PORT="$(prompt "Keycloak bind port (host-local, nur relevant bei internem Keycloak)" "8081")"
HUB_BIND_PORT="$(prompt "Hub bind port (host-local)" "8082")"

BIND_PUBLIC="$(prompt_bool "Ports öffentlich binden (0.0.0.0) statt nur localhost?" "no")"
if [[ "$BIND_PUBLIC" == "yes" ]]; then
  BIND_IP="0.0.0.0"
else
  BIND_IP="127.0.0.1"
fi

# Images
POSTGRES_IMAGE="$(prompt "Postgres Image" "postgres:14-alpine")"
HUB_IMAGE="$(prompt "Hub Image" "ghcr.io/cryptomator/hub:stable")"
KEYCLOAK_IMAGE_DEFAULT="ghcr.io/cryptomator/keycloak:26.5.3"
KEYCLOAK_IMAGE="$KEYCLOAK_IMAGE_DEFAULT"
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  KEYCLOAK_IMAGE="$(prompt "Keycloak Image" "$KEYCLOAK_IMAGE_DEFAULT")"
fi

# Keycloak/Realm parameters
EXTERNAL_KC_REALM="cryptomator"
KC_RELATIVE_PATH="/kc"

# Redirect URI for hub client
HUB_REDIRECT_URI_DEFAULT="${HUB_PUBLIC_BASE%/}/*"
HUB_REDIRECT_URI="$(prompt "Hub Redirect URI (Keycloak client cryptomatorhub), z.B. https://hub.example.tld/*" "$HUB_REDIRECT_URI_DEFAULT")"

# Hub OIDC client id
HUB_OIDC_CLIENT_ID="$(prompt "OIDC Client ID (Hub)" "cryptomatorhub")"

# System client (used by Hub to manage users/groups)
HUB_SYSTEM_CLIENT_ID="$(prompt "System Client ID (Keycloak)" "cryptomatorhub-system")"

# External Keycloak specific
KC_INTERNAL_URL="${KC_PUBLIC_BASE%/}"  # URL reachable from Hub container
EXTERNAL_KC_ISSUER=""
EXTERNAL_KC_AUTH_SERVER_URL=""

HUB_SYSTEM_CLIENT_SECRET=""
REALM_ADMIN_USER="admin"
REALM_ADMIN_PASSWORD=""
REALM_ADMIN_TEMP="true"

if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  EXTERNAL_KC_REALM="$(prompt "Externer Keycloak Realm" "cryptomator")"
  KC_INTERNAL_URL="$(prompt "Keycloak interne URL (vom Hub-Container erreichbar). Oft identisch zur Public URL" "${KC_PUBLIC_BASE%/}")"
  EXTERNAL_KC_ISSUER_DEFAULT="${KC_PUBLIC_BASE%/}/realms/${EXTERNAL_KC_REALM}"
  EXTERNAL_KC_ISSUER="$(prompt "OIDC Issuer (z.B. https://auth.example.tld/realms/cryptomator)" "$EXTERNAL_KC_ISSUER_DEFAULT")"
  EXTERNAL_KC_AUTH_SERVER_URL="$(prompt "OIDC Auth Server URL (Hub QUARKUS_OIDC_AUTH_SERVER_URL). Oft identisch zum Issuer" "$EXTERNAL_KC_ISSUER")"
  HUB_SYSTEM_CLIENT_SECRET="$(prompt "System Client Secret (vom externen Keycloak)" "")"
  [[ -n "$HUB_SYSTEM_CLIENT_SECRET" ]] || err "System Client Secret darf nicht leer sein (External Keycloak)."
else
  KC_RELATIVE_PATH="$(prompt "Keycloak Relative Path" "/kc")"

  # Realm bootstrap admin
  REALM_ADMIN_USER="$(prompt "Initialer Realm-Admin Username (cryptomator realm)" "admin")"
  REALM_ADMIN_PASSWORD="$(rand_b64 18)"
  REALM_ADMIN_TEMP_Q="$(prompt_bool "Realm-Admin Passwort bei erstem Login erzwingen (temporary)?" "yes")"
  if [[ "$REALM_ADMIN_TEMP_Q" == "yes" ]]; then
    REALM_ADMIN_TEMP="true"
  else
    REALM_ADMIN_TEMP="false"
  fi
fi

### ---------------------------
### Validate
### ---------------------------
if pct status "$CTID" >/dev/null 2>&1; then
  err "CTID $CTID existiert bereits. Bitte andere CTID wählen oder Container entfernen."
fi

[[ "$CORES" =~ ^[0-9]+$ ]] || err "CORES muss numerisch sein."
[[ "$RAM" =~ ^[0-9]+$ ]] || err "RAM muss numerisch sein."
[[ "$DISK_GB" =~ ^[0-9]+$ ]] || err "DISK_GB muss numerisch sein."
[[ "$SWAP_MB" =~ ^[0-9]+$ ]] || err "SWAP_MB muss numerisch sein."

### ---------------------------
### Download LXC template if needed
### ---------------------------
TEMPLATE="debian-12-standard_12.7-1_amd64.tar.zst"

info "Prüfe LXC Template: $TEMPLATE"
if ! pveam list local | awk '{print $1}' | grep -qx "$TEMPLATE"; then
  info "Template nicht vorhanden. Lade herunter..."
  pveam update >/dev/null
  pveam download local "$TEMPLATE"
fi

### ---------------------------
### Create LXC
### ---------------------------
info "Erstelle LXC CT $CTID ($HOSTNAME)"

NET_CONF="name=eth0,bridge=${BRIDGE},firewall=1"
if [[ "$USE_DHCP" == "yes" ]]; then
  NET_CONF="${NET_CONF},ip=dhcp"
else
  [[ -n "$IP_CIDR" && -n "$GATEWAY" ]] || err "Für statische IP müssen IP_CIDR und GATEWAY gesetzt sein."
  NET_CONF="${NET_CONF},ip=${IP_CIDR},gw=${GATEWAY}"
fi

pct create "$CTID" "local:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$RAM" \
  --swap "$SWAP_MB" \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "$NET_CONF" \
  --features "nesting=1,keyctl=1" \
  --unprivileged 1 \
  --onboot 1 \
  --ostype debian \
  --timezone "$TZ"

if [[ "$USE_DHCP" == "no" ]]; then
  pct set "$CTID" --nameserver "$DNS_SERVER"
fi

info "Starte LXC CT $CTID"
pct start "$CTID"
info "Warte kurz auf Boot..."
sleep 5

### ---------------------------
### Install Docker inside LXC
### ---------------------------
info "Installiere Docker + Compose im LXC"

pct_exec "$CTID" "apt-get update"
pct_exec "$CTID" "apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https"

pct_exec "$CTID" "install -m 0755 -d /etc/apt/keyrings"
pct_exec "$CTID" "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
pct_exec "$CTID" "chmod a+r /etc/apt/keyrings/docker.gpg"
pct_exec "$CTID" "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \$(. /etc/os-release && echo \$VERSION_CODENAME) stable\" > /etc/apt/sources.list.d/docker.list"
pct_exec "$CTID" "apt-get update"
pct_exec "$CTID" "apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
pct_exec "$CTID" "systemctl enable --now docker"

### ---------------------------
### Generate secrets and config
### ---------------------------
info "Erzeuge Secrets und Konfiguration"

APP_DIR="/opt/cryptomator-hub"
DATA_DIR="${APP_DIR}/data"
DB_DATA_DIR="${DATA_DIR}/db-data"
DB_INIT_DIR="${DATA_DIR}/db-init"
KC_IMPORT_DIR="${DATA_DIR}/kc-import"

pct_exec "$CTID" "mkdir -p '${APP_DIR}' '${DB_DATA_DIR}' '${DB_INIT_DIR}'"
pct_exec "$CTID" "chmod 755 '${APP_DIR}'"
pct_exec "$CTID" "chmod 700 '${DATA_DIR}' || true"

POSTGRES_PASSWORD="$(rand_hex 24)"
HUB_DB_PASSWORD="$(rand_hex 24)"

# Internal Keycloak secrets
KC_DB_PASSWORD=""
KEYCLOAK_ADMIN_PASSWORD=""
HUB_SYSTEM_CLIENT_SECRET_INTERNAL=""
REALM_ID=""

if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  pct_exec "$CTID" "mkdir -p '${KC_IMPORT_DIR}'"
  KC_DB_PASSWORD="$(rand_hex 24)"
  KEYCLOAK_ADMIN_PASSWORD="$(rand_b64 24)"
  HUB_SYSTEM_CLIENT_SECRET_INTERNAL="$(rand_hex 24)"
  HUB_SYSTEM_CLIENT_SECRET="$HUB_SYSTEM_CLIENT_SECRET_INTERNAL"
  REALM_ID="$(uuid_any)"
fi

# initdb.sql (postgres init script)
if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  INITDB_SQL=$(cat <<EOF
CREATE USER hub WITH ENCRYPTED PASSWORD '${HUB_DB_PASSWORD}';
CREATE DATABASE hub WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE hub TO hub;
EOF
)
else
  INITDB_SQL=$(cat <<EOF
CREATE USER keycloak WITH ENCRYPTED PASSWORD '${KC_DB_PASSWORD}';
CREATE DATABASE keycloak WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

CREATE USER hub WITH ENCRYPTED PASSWORD '${HUB_DB_PASSWORD}';
CREATE DATABASE hub WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE hub TO hub;
EOF
)
fi

# realm.json only for internal Keycloak
REALM_JSON=""
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  # requiredActions depends on temporary setting
  if [[ "$REALM_ADMIN_TEMP" == "true" ]]; then
    REQUIRED_ACTIONS='["UPDATE_PASSWORD"]'
  else
    REQUIRED_ACTIONS='[]'
  fi

  HUB_PUBLIC_BASE_NOSLASH="${HUB_PUBLIC_BASE%/}"

  REALM_JSON=$(cat <<EOF
{
  "id": "${REALM_ID}",
  "realm": "cryptomator",
  "displayName": "Cryptomator Hub",
  "loginTheme": "cryptomator",
  "enabled": true,
  "sslRequired": "external",
  "defaultRole": { "name": "user", "description": "User" },
  "roles": {
    "realm": [
      { "name": "user", "description": "User", "composite": false },
      { "name": "create-vaults", "description": "Can create vaults", "composite": false },
      {
        "name": "admin",
        "description": "Administrator",
        "composite": true,
        "composites": {
          "realm": [ "user", "create-vaults" ],
          "client": { "realm-management": [ "realm-admin" ] }
        }
      }
    ]
  },
  "users": [
    {
      "username": "${REALM_ADMIN_USER}",
      "enabled": true,
      "credentials": [
        { "type": "password", "value": "${REALM_ADMIN_PASSWORD}", "temporary": ${REALM_ADMIN_TEMP} }
      ],
      "requiredActions": ${REQUIRED_ACTIONS},
      "realmRoles": [ "admin" ]
    },
    {
      "username": "system",
      "email": "system@localhost",
      "enabled": true,
      "serviceAccountClientId": "${HUB_SYSTEM_CLIENT_ID}",
      "clientRoles": { "realm-management": [ "realm-admin", "view-system" ] }
    }
  ],
  "scopeMappings": [
    { "client": "${HUB_OIDC_CLIENT_ID}", "roles": [ "user", "admin" ] }
  ],
  "clients": [
    {
      "clientId": "${HUB_OIDC_CLIENT_ID}",
      "serviceAccountsEnabled": false,
      "publicClient": true,
      "name": "Cryptomator Hub",
      "enabled": true,
      "redirectUris": [ "${HUB_REDIRECT_URI}" ],
      "webOrigins": [ "+" ],
      "bearerOnly": false,
      "frontchannelLogout": false,
      "protocol": "openid-connect",
      "attributes": { "pkce.code.challenge.method": "S256" },
      "protocolMappers": [
        {
          "name": "realm roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "consentRequired": false,
          "config": {
            "access.token.claim": "true",
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        },
        {
          "name": "client roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-client-role-mapper",
          "consentRequired": false,
          "config": {
            "access.token.claim": "true",
            "claim.name": "resource_access.\$\${client_id}.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        }
      ]
    },
    {
      "clientId": "cryptomator",
      "serviceAccountsEnabled": false,
      "publicClient": true,
      "name": "Cryptomator App",
      "enabled": true,
      "redirectUris": [
        "http://127.0.0.1/*",
        "org.cryptomator.ios:/hub/auth",
        "org.cryptomator.android:/hub/auth"
      ],
      "webOrigins": [ "+" ],
      "bearerOnly": false,
      "frontchannelLogout": false,
      "protocol": "openid-connect",
      "attributes": { "pkce.code.challenge.method": "S256" }
    },
    {
      "clientId": "${HUB_SYSTEM_CLIENT_ID}",
      "serviceAccountsEnabled": true,
      "publicClient": false,
      "name": "Cryptomator Hub System",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "${HUB_SYSTEM_CLIENT_SECRET}",
      "standardFlowEnabled": false
    }
  ],
  "browserSecurityHeaders": {
    "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self' ${HUB_PUBLIC_BASE_NOSLASH}/; object-src 'none';"
  }
}
EOF
)
fi

# .env content
ENV_CONTENT=$(cat <<EOF
# Cryptomator Hub deployment (.env)
# WICHTIG: Diese Datei enthält Secrets. Nicht in Git einchecken.

# Variant
USE_EXTERNAL_KC=${USE_EXTERNAL_KC}

# Images
POSTGRES_IMAGE=${POSTGRES_IMAGE}
HUB_IMAGE=${HUB_IMAGE}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE}

# Bindings
BIND_IP=${BIND_IP}
KC_BIND_PORT=${KC_BIND_PORT}
HUB_BIND_PORT=${HUB_BIND_PORT}

# Public URLs
HUB_PUBLIC_BASE=${HUB_PUBLIC_BASE%/}
KC_PUBLIC_BASE=${KC_PUBLIC_BASE%/}
KC_RELATIVE_PATH=${KC_RELATIVE_PATH}

# Database
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
HUB_DB_PASSWORD=${HUB_DB_PASSWORD}
KC_DB_PASSWORD=${KC_DB_PASSWORD}

# Hub OIDC
HUB_OIDC_CLIENT_ID=${HUB_OIDC_CLIENT_ID}
HUB_SYSTEM_CLIENT_ID=${HUB_SYSTEM_CLIENT_ID}
HUB_SYSTEM_CLIENT_SECRET=${HUB_SYSTEM_CLIENT_SECRET}

# External Keycloak (nur wenn USE_EXTERNAL_KC=yes)
EXTERNAL_KC_REALM=${EXTERNAL_KC_REALM}
KC_INTERNAL_URL=${KC_INTERNAL_URL}
EXTERNAL_KC_ISSUER=${EXTERNAL_KC_ISSUER}
EXTERNAL_KC_AUTH_SERVER_URL=${EXTERNAL_KC_AUTH_SERVER_URL}

# Redirect URI for hub client
HUB_REDIRECT_URI=${HUB_REDIRECT_URI}

# Internal Keycloak bootstrap (nur wenn USE_EXTERNAL_KC=no)
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}
REALM_ADMIN_USER=${REALM_ADMIN_USER}
REALM_ADMIN_PASSWORD=${REALM_ADMIN_PASSWORD}
REALM_ADMIN_TEMPORARY=${REALM_ADMIN_TEMP}
EOF
)

# compose.yml content (two variants)
if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  COMPOSE_CONTENT=$(cat <<EOF
services:
  postgres:
    image: \${POSTGRES_IMAGE}
    volumes:
      - ${DB_INIT_DIR}:/docker-entrypoint-initdb.d
      - ${DB_DATA_DIR}:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8

  hub:
    image: \${HUB_IMAGE}
    depends_on:
      - postgres
    ports:
      - "\${BIND_IP}:\${HUB_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      HUB_PUBLIC_ROOT_PATH: /
      # Public URL des Keycloak (Issuer/Browser)
      HUB_KEYCLOAK_PUBLIC_URL: \${KC_PUBLIC_BASE}
      # Interne URL (vom Hub-Container erreichbar)
      HUB_KEYCLOAK_LOCAL_URL: \${KC_INTERNAL_URL}
      HUB_KEYCLOAK_REALM: \${EXTERNAL_KC_REALM}
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: \${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: \${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m

      # Cryptomator App client id bleibt "cryptomator" (wie in offiziellen Defaults)
      HUB_KEYCLOAK_OIDC_CRYPTOMATOR_CLIENT_ID: cryptomator

      QUARKUS_OIDC_AUTH_SERVER_URL: \${EXTERNAL_KC_AUTH_SERVER_URL}
      QUARKUS_OIDC_TOKEN_ISSUER: \${EXTERNAL_KC_ISSUER}
      QUARKUS_OIDC_CLIENT_ID: \${HUB_OIDC_CLIENT_ID}

      QUARKUS_DATASOURCE_JDBC_URL: jdbc:postgresql://postgres:5432/hub
      QUARKUS_DATASOURCE_USERNAME: hub
      QUARKUS_DATASOURCE_PASSWORD: \${HUB_DB_PASSWORD}
      QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING: "true"
EOF
)
else
  COMPOSE_CONTENT=$(cat <<EOF
services:
  postgres:
    image: \${POSTGRES_IMAGE}
    volumes:
      - ${DB_INIT_DIR}:/docker-entrypoint-initdb.d
      - ${DB_DATA_DIR}:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8

  keycloak:
    image: \${KEYCLOAK_IMAGE}
    depends_on:
      - postgres
    command: start --optimized --import-realm
    volumes:
      - ${KC_IMPORT_DIR}:/opt/keycloak/data/import
    ports:
      - "\${BIND_IP}:\${KC_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      KEYCLOAK_ADMIN: \${KEYCLOAK_ADMIN_USER}
      KEYCLOAK_ADMIN_PASSWORD: \${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: \${KC_DB_PASSWORD}
      KC_HEALTH_ENABLED: "true"
      KC_HTTP_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_RELATIVE_PATH: \${KC_RELATIVE_PATH}
      KC_HOSTNAME: \${KC_PUBLIC_BASE}

  hub:
    image: \${HUB_IMAGE}
    depends_on:
      - postgres
      - keycloak
    ports:
      - "\${BIND_IP}:\${HUB_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      HUB_PUBLIC_ROOT_PATH: /
      HUB_KEYCLOAK_PUBLIC_URL: \${KC_PUBLIC_BASE}
      HUB_KEYCLOAK_LOCAL_URL: http://keycloak:8080\${KC_RELATIVE_PATH}
      HUB_KEYCLOAK_REALM: cryptomator
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: \${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: \${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m
      HUB_KEYCLOAK_OIDC_CRYPTOMATOR_CLIENT_ID: cryptomator

      QUARKUS_OIDC_AUTH_SERVER_URL: http://keycloak:8080\${KC_RELATIVE_PATH}/realms/cryptomator
      QUARKUS_OIDC_TOKEN_ISSUER: \${KC_PUBLIC_BASE}/realms/cryptomator
      QUARKUS_OIDC_CLIENT_ID: \${HUB_OIDC_CLIENT_ID}

      QUARKUS_DATASOURCE_JDBC_URL: jdbc:postgresql://postgres:5432/hub
      QUARKUS_DATASOURCE_USERNAME: hub
      QUARKUS_DATASOURCE_PASSWORD: \${HUB_DB_PASSWORD}
      QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING: "true"
EOF
)
fi

### ---------------------------
### Push files into LXC
### ---------------------------
info "Schreibe Dateien in den LXC: ${APP_DIR}"

# Write initdb.sql
pct_push_str "$CTID" "${DB_INIT_DIR}/initdb.sql" "$INITDB_SQL"
pct_exec "$CTID" "chmod 600 '${DB_INIT_DIR}/initdb.sql'"

# Write realm.json if internal
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  pct_push_str "$CTID" "${KC_IMPORT_DIR}/realm.json" "$REALM_JSON"
  pct_exec "$CTID" "chmod 600 '${KC_IMPORT_DIR}/realm.json'"
fi

# Write compose and env
pct_push_str "$CTID" "${APP_DIR}/compose.yml" "$COMPOSE_CONTENT"
pct_push_str "$CTID" "${APP_DIR}/.env" "$ENV_CONTENT"
pct_exec "$CTID" "chmod 644 '${APP_DIR}/compose.yml'"
pct_exec "$CTID" "chmod 600 '${APP_DIR}/.env'"

### ---------------------------
### Start stack
### ---------------------------
info "Starte Container (docker compose up -d)"
pct_exec "$CTID" "cd '${APP_DIR}' && docker compose --env-file .env -f compose.yml up -d"

### ---------------------------
### Summary
### ---------------------------
echo ""
echo "===== Zusammenfassung ====="
echo "LXC CTID:                 $CTID"
echo "LXC Hostname:             $HOSTNAME"
echo "Installationspfad (LXC):  $APP_DIR"
echo "Variante:                 $( [[ "$USE_EXTERNAL_KC" == "yes" ]] && echo "External Keycloak" || echo "Internal Keycloak" )"
echo ""
echo "Hub (lokal):              http://${BIND_IP}:${HUB_BIND_PORT}/"
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  echo "Keycloak (lokal):          http://${BIND_IP}:${KC_BIND_PORT}${KC_RELATIVE_PATH}"
fi
echo ""
echo "Hub Public Base:          ${HUB_PUBLIC_BASE%/}"
echo "Keycloak Public Base:     ${KC_PUBLIC_BASE%/}"
echo ""

if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  echo "External Keycloak Realm:  ${EXTERNAL_KC_REALM}"
  echo "OIDC Issuer:              ${EXTERNAL_KC_ISSUER}"
  echo "OIDC Auth Server URL:     ${EXTERNAL_KC_AUTH_SERVER_URL}"
  echo ""
  echo "Wichtig (External):"
  echo "- Stelle sicher, dass im Keycloak folgende Objekte existieren:"
  echo "  - Realm:                 ${EXTERNAL_KC_REALM}"
  echo "  - Client (Hub):          ${HUB_OIDC_CLIENT_ID} (public client, Redirect URI: ${HUB_REDIRECT_URI})"
  echo "  - Client (System):       ${HUB_SYSTEM_CLIENT_ID} (confidential, secret: <dein Secret>)"
  echo "  - Client (Cryptomator):  cryptomator (redirectUris: mobile/localhost wie üblich)"
else
  echo "Keycloak Admin (container env):"
  echo "  User:                   admin"
  echo "  Password:               ${KEYCLOAK_ADMIN_PASSWORD}"
  echo ""
  echo "Realm Admin (cryptomator realm):"
  echo "  User:                   ${REALM_ADMIN_USER}"
  echo "  Password:               ${REALM_ADMIN_PASSWORD}"
  echo "  Temporary Password:     ${REALM_ADMIN_TEMP}"
  echo ""
  echo "Wichtig (Internal):"
  echo "- Wenn du KC_PUBLIC_BASE oder KC_RELATIVE_PATH später änderst, entferne '--optimized' aus dem Keycloak command,"
  echo "  sonst startet Keycloak nicht."
fi

echo ""
echo "Logs (im LXC):"
echo "  cd ${APP_DIR} && docker compose --env-file .env -f compose.yml logs -f"
echo "==========================="