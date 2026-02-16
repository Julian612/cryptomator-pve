#!/usr/bin/env bash
# cryptomator-hub-pve.sh
#
# Proxmox VE helper-artiges Install-Script für Cryptomator Hub in Debian 12 LXC (Docker Compose)
#
# Varianten:
#  - Internal Keycloak: Postgres + Keycloak + Hub (Realm/Clients via realm.json Import)
#  - External Keycloak: Postgres + Hub (Keycloak existiert extern; Realm/Clients/Secrets extern bereitstellen)
#
# UI:
#  - Whiptail (Proxmox-Helper-Look & Feel: graues Fenster, blauer Hintergrund)
#  - Defaults werden angezeigt und bei ENTER übernommen
#
# Robustheit:
#  - Template wird NICHT hardcodiert, sondern automatisch via `pveam available` als neuestes Debian-12-Template ermittelt
#  - Template-Storage (vztmpl) wird ausgewählt/validiert
#  - URLs werden normalisiert (fehlendes https:// wird ergänzt)
#  - Images werden validiert (image:tag)
#
# Ausführung:
#  - Auf dem Proxmox Host als root
#
# Sicherheit:
#  - Secrets werden im LXC unter /opt/cryptomator-hub/.env gespeichert (chmod 600). Nicht ins Git einchecken.

set -euo pipefail

### ---------------------------
### UI: Proxmox Helper Look & Feel
### ---------------------------
export NEWT_COLORS='
root=white,blue
window=black,lightgray
border=black,lightgray
textbox=black,lightgray
button=white,blue
actbutton=white,blue
compactbutton=white,blue
entry=black,lightgray
label=black,lightgray
listbox=black,lightgray
actsellistbox=white,blue
sellistbox=black,lightgray
'

### ---------------------------
### Helpers
### ---------------------------
err() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Fehlendes Kommando: $1"; }

ensure_whiptail() {
  if command -v whiptail >/dev/null 2>&1; then return 0; fi
  echo "whiptail nicht gefunden. Installiere..."
  apt-get update -y >/dev/null
  apt-get install -y whiptail >/dev/null
}

ui_msg() { whiptail --title "${1:-Info}" --msgbox "${2:-}" 12 80; }
ui_yesno() { whiptail --title "${1:-Frage}" --yesno "${2:-}" 12 80; } # 0=yes 1=no

ui_input() { # ui_input "title" "text" "default" -> stdout ; ENTER => default
  local title="$1" text="$2" def="${3:-}"
  local out
  out="$(whiptail --title "$title" --inputbox "$text" 12 80 "$def" 3>&1 1>&2 2>&3)" || exit 1
  if [[ -z "$out" ]]; then
    echo "$def"
  else
    echo "$out"
  fi
}

ui_menu() { # ui_menu "title" "text" h w lh items... -> stdout
  local title="$1" text="$2" h="${3:-16}" w="${4:-80}" lh="${5:-8}"
  shift 5
  local out
  out="$(whiptail --title "$title" --menu "$text" "$h" "$w" "$lh" "$@" 3>&1 1>&2 2>&3)" || exit 1
  echo "$out"
}

rand_hex() { local n="${1:-24}"; openssl rand -hex "$n"; }
rand_b64() { local n="${1:-24}"; openssl rand -base64 "$n" | tr -d '\n'; }

pct_exec() { local ctid="$1"; shift; pct exec "$ctid" -- bash -lc "$*"; }

pct_push_str() { # pct_push_str CTID /path "content" perms
  local ctid="$1" path="$2" content="$3" perms="${4:-0644}"
  local tmp
  tmp="$(mktemp)"
  printf "%s" "$content" >"$tmp"
  pct push "$ctid" "$tmp" "$path" --perms "$perms"
  rm -f "$tmp"
}

uuid_any() { if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi; }

normalise_url() {
  local u="$1"
  if [[ "$u" != http*://* ]]; then
    echo "https://${u}"
  else
    echo "$u"
  fi
}

validate_image() {
  local v="$1" label="$2"
  [[ "$v" == *:* ]] || err "$label muss Format image:tag haben (z.B. postgres:14-alpine). Eingabe: '$v'"
}

### ---------------------------
### Preflight
### ---------------------------
[[ "$(id -u)" -eq 0 ]] || err "Bitte als root auf dem Proxmox VE Host ausführen."
need_cmd pveversion
need_cmd pct
need_cmd pveam
need_cmd pvesm
need_cmd openssl
need_cmd awk
need_cmd sed
need_cmd grep
ensure_whiptail

ui_msg "Cryptomator Hub Installer" "Dieses Script deployt Cryptomator Hub in einem Debian 12 LXC auf Proxmox VE.\n\nVariante wählbar:\n- Internal Keycloak\n- External Keycloak\n\nAbbruch jederzeit mit ESC."

### ---------------------------
### Variante wählen
### ---------------------------
MODE="$(ui_menu "Variante" "Welche Variante willst du deployen?" 14 80 5 \
  "internal" "Internal Keycloak (Postgres + Keycloak + Hub)" \
  "external" "External Keycloak (Postgres + Hub, Keycloak existiert extern)")"

USE_EXTERNAL_KC="no"
[[ "$MODE" == "external" ]] && USE_EXTERNAL_KC="yes"

### ---------------------------
### LXC Basis
### ---------------------------
CTID="$(ui_input "LXC" "CTID (numerisch)\n\nHinweis: muss frei sein." "120")"
[[ "$CTID" =~ ^[0-9]+$ ]] || err "CTID muss numerisch sein."
if pct status "$CTID" >/dev/null 2>&1; then
  err "CTID $CTID existiert bereits. Bitte andere CTID wählen oder Container entfernen."
fi

HOSTNAME="$(ui_input "LXC" "Hostname des LXC" "cryptomator-hub")"
TZ="$(ui_input "LXC" "Zeitzone im LXC" "Europe/Zurich")"

CORES="$(ui_input "Ressourcen" "CPU Cores" "2")"
RAM="$(ui_input "Ressourcen" "RAM (MB)" "2048")"
DISK_GB="$(ui_input "Ressourcen" "Disk (GB) – RootFS Grösse" "16")"
SWAP_MB="$(ui_input "Ressourcen" "Swap (MB)" "512")"
[[ "$CORES" =~ ^[0-9]+$ && "$RAM" =~ ^[0-9]+$ && "$DISK_GB" =~ ^[0-9]+$ && "$SWAP_MB" =~ ^[0-9]+$ ]] || err "Ressourcenwerte müssen numerisch sein."

### ---------------------------
### Storage
### ---------------------------
STORAGE_ROOTFS="$(ui_input "Storage" "Proxmox Storage für RootFS\n\nBeispiel: local-lvm, zfs, SSDStorage" "local-lvm")"

mapfile -t VZT_STORAGES < <(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1{print $1}' | sort -u)
if [[ "${#VZT_STORAGES[@]}" -eq 0 ]]; then
  TEMPLATE_STORAGE="$(ui_input "Templates" "Storage für LXC Templates (Content: vztmpl)\n\nHinweis: Oft 'local'." "local")"
else
  MENU_ITEMS=()
  for s in "${VZT_STORAGES[@]}"; do MENU_ITEMS+=("$s" "Storage mit vztmpl"); done
  TEMPLATE_STORAGE="$(ui_menu "Templates" "Wähle Storage für LXC Templates (vztmpl)" 14 80 6 "${MENU_ITEMS[@]}")"
fi

### ---------------------------
### Netzwerk
### ---------------------------
BRIDGE="$(ui_input "Netzwerk" "Network Bridge (z.B. vmbr0)" "vmbr0")"
if ui_yesno "Netzwerk" "Netzwerk via DHCP verwenden?"; then
  USE_DHCP="yes"
else
  USE_DHCP="no"
fi

IP_CIDR=""
GATEWAY=""
DNS_SERVER=""
if [[ "$USE_DHCP" == "no" ]]; then
  IP_CIDR="$(ui_input "Netzwerk" "Statische IP inkl. CIDR (z.B. 192.168.1.50/24)" "")"
  GATEWAY="$(ui_input "Netzwerk" "Gateway (z.B. 192.168.1.1)" "")"
  DNS_SERVER="$(ui_input "Netzwerk" "DNS Server (z.B. 1.1.1.1)" "1.1.1.1")"
  [[ -n "$IP_CIDR" && -n "$GATEWAY" ]] || err "Für statische IP müssen IP_CIDR und GATEWAY gesetzt sein."
fi

### ---------------------------
### URLs / Ports / Images
### ---------------------------
HUB_PUBLIC_BASE="$(ui_input "URLs" "Hub Public Base URL\n\nBeispiel: https://cryptomator.example.tld" "https://cryptomator.example.tld")"
KC_PUBLIC_BASE="$(ui_input "URLs" "Keycloak Public Base URL\n\nBeispiel: https://auth.example.tld oder https://example.tld/kc" "https://auth.example.tld")"
HUB_PUBLIC_BASE="$(normalise_url "$HUB_PUBLIC_BASE")"
KC_PUBLIC_BASE="$(normalise_url "$KC_PUBLIC_BASE")"

KC_BIND_PORT="8081"
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  KC_BIND_PORT="$(ui_input "Ports" "Keycloak bind port (host-local)\n\nReverse Proxy forwarded to this port." "8081")"
fi
HUB_BIND_PORT="$(ui_input "Ports" "Hub bind port (host-local)\n\nReverse Proxy forwarded to this port." "8082")"

if ui_yesno "Ports" "Ports öffentlich binden (0.0.0.0) statt nur localhost?\n\nEmpfehlung: Nein (Reverse Proxy verwenden)."; then
  BIND_IP="0.0.0.0"
else
  BIND_IP="127.0.0.1"
fi

POSTGRES_IMAGE="$(ui_input "Images" "Postgres Image\n\nDefault wird bei ENTER übernommen." "postgres:14-alpine")"
HUB_IMAGE="$(ui_input "Images" "Hub Image\n\nDefault wird bei ENTER übernommen." "ghcr.io/cryptomator/hub:stable")"
validate_image "$POSTGRES_IMAGE" "Postgres Image"
validate_image "$HUB_IMAGE" "Hub Image"

KEYCLOAK_IMAGE="ghcr.io/cryptomator/keycloak:26.5.3"
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  KEYCLOAK_IMAGE="$(ui_input "Images" "Keycloak Image\n\nDefault wird bei ENTER übernommen." "ghcr.io/cryptomator/keycloak:26.5.3")"
  validate_image "$KEYCLOAK_IMAGE" "Keycloak Image"
fi

### ---------------------------
### OIDC / Clients
### ---------------------------
HUB_REDIRECT_URI_DEFAULT="${HUB_PUBLIC_BASE%/}/*"
HUB_REDIRECT_URI="$(ui_input "OIDC" "Hub Redirect URI (Keycloak client: cryptomatorhub)\n\nBeispiel: ${HUB_REDIRECT_URI_DEFAULT}" "$HUB_REDIRECT_URI_DEFAULT")"

HUB_OIDC_CLIENT_ID="$(ui_input "OIDC" "OIDC Client ID (Hub)" "cryptomatorhub")"
HUB_SYSTEM_CLIENT_ID="$(ui_input "OIDC" "System Client ID (Keycloak)" "cryptomatorhub-system")"

KC_RELATIVE_PATH="/kc"

EXTERNAL_KC_REALM="cryptomator"
KC_INTERNAL_URL="${KC_PUBLIC_BASE%/}"
EXTERNAL_KC_ISSUER=""
EXTERNAL_KC_AUTH_SERVER_URL=""
HUB_SYSTEM_CLIENT_SECRET=""

REALM_ADMIN_USER="admin"
REALM_ADMIN_PASSWORD=""
REALM_ADMIN_TEMP="true"

if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  EXTERNAL_KC_REALM="$(ui_input "External Keycloak" "Realm Name im externen Keycloak" "cryptomator")"
  KC_INTERNAL_URL="$(ui_input "External Keycloak" "Keycloak interne URL (vom Hub-Container erreichbar)\n\nOft identisch zur Public URL." "${KC_PUBLIC_BASE%/}")"
  EXTERNAL_KC_ISSUER_DEFAULT="${KC_PUBLIC_BASE%/}/realms/${EXTERNAL_KC_REALM}"
  EXTERNAL_KC_ISSUER="$(ui_input "External Keycloak" "OIDC Issuer\n\nBeispiel: ${EXTERNAL_KC_ISSUER_DEFAULT}" "$EXTERNAL_KC_ISSUER_DEFAULT")"
  EXTERNAL_KC_AUTH_SERVER_URL="$(ui_input "External Keycloak" "OIDC Auth Server URL (QUARKUS_OIDC_AUTH_SERVER_URL)\n\nOft identisch zum Issuer." "$EXTERNAL_KC_ISSUER")"
  HUB_SYSTEM_CLIENT_SECRET="$(ui_input "External Keycloak" "System Client Secret (aus externem Keycloak)\n\nWichtig: nicht leer." "")"
  [[ -n "$HUB_SYSTEM_CLIENT_SECRET" ]] || err "System Client Secret darf nicht leer sein (External Keycloak)."
else
  KC_RELATIVE_PATH="$(ui_input "Keycloak" "Keycloak Relative Path" "/kc")"
  REALM_ADMIN_USER="$(ui_input "Keycloak" "Initialer Realm-Admin Username (cryptomator realm)" "admin")"
  if ui_yesno "Keycloak" "Realm-Admin Passwort bei erstem Login erzwingen (temporary)?"; then
    REALM_ADMIN_TEMP="true"
  else
    REALM_ADMIN_TEMP="false"
  fi
fi

### ---------------------------
### Template ermitteln (nicht hardcodiert) + downloaden
### ---------------------------
info "Aktualisiere Template-Katalog (pveam update)"
pveam update >/dev/null

if ! pvesm status --content vztmpl 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$TEMPLATE_STORAGE"; then
  err "Der gewählte Template-Storage '$TEMPLATE_STORAGE' unterstützt kein 'vztmpl'. Wähle einen Storage mit Content 'vztmpl' (z.B. local)."
fi

TEMPLATE="$(pveam available --section system 2>/dev/null \
  | awk '{print $2}' \
  | grep -E '^debian-12-standard_.*_amd64\.tar\.zst$' \
  | sort -V \
  | tail -n 1)"

if [[ -z "${TEMPLATE:-}" ]]; then
  err "Konnte kein Debian-12-Template via 'pveam available' finden. Prüfe Internet/DNS oder Proxmox Repo-Konfiguration."
fi

info "Verwende LXC Template: $TEMPLATE (Storage: $TEMPLATE_STORAGE)"

if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | awk '{print $1}' | grep -qx "$TEMPLATE"; then
  info "Template nicht vorhanden. Lade herunter..."
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

### ---------------------------
### LXC erstellen
### ---------------------------
NET_CONF="name=eth0,bridge=${BRIDGE},firewall=1"
if [[ "$USE_DHCP" == "yes" ]]; then
  NET_CONF="${NET_CONF},ip=dhcp"
else
  NET_CONF="${NET_CONF},ip=${IP_CIDR},gw=${GATEWAY}"
fi

info "Erstelle LXC CT $CTID ($HOSTNAME)"
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$RAM" \
  --swap "$SWAP_MB" \
  --rootfs "${STORAGE_ROOTFS}:${DISK_GB}" \
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
sleep 5

### ---------------------------
### Docker im LXC installieren
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
### Konfiguration erzeugen
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

KC_DB_PASSWORD=""
KEYCLOAK_ADMIN_PASSWORD=""
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  pct_exec "$CTID" "mkdir -p '${KC_IMPORT_DIR}'"
  KC_DB_PASSWORD="$(rand_hex 24)"
  KEYCLOAK_ADMIN_PASSWORD="$(rand_b64 24)"
  HUB_SYSTEM_CLIENT_SECRET="$(rand_hex 24)"
  REALM_ADMIN_PASSWORD="$(rand_b64 18)"
fi

# initdb.sql
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

# realm.json (nur internal)
REALM_JSON=""
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  REALM_ID="$(uuid_any)"
  HUB_PUBLIC_BASE_NOSLASH="${HUB_PUBLIC_BASE%/}"

  if [[ "$REALM_ADMIN_TEMP" == "true" ]]; then
    REQUIRED_ACTIONS='["UPDATE_PASSWORD"]'
  else
    REQUIRED_ACTIONS='[]'
  fi

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
      "attributes": { "pkce.code.challenge.method": "S256" }
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

# .env
ENV_CONTENT=$(cat <<EOF
# Cryptomator Hub deployment (.env)
# WICHTIG: Diese Datei enthält Secrets. Nicht in Git einchecken.

USE_EXTERNAL_KC=${USE_EXTERNAL_KC}

POSTGRES_IMAGE=${POSTGRES_IMAGE}
HUB_IMAGE=${HUB_IMAGE}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE}

BIND_IP=${BIND_IP}
KC_BIND_PORT=${KC_BIND_PORT}
HUB_BIND_PORT=${HUB_BIND_PORT}

HUB_PUBLIC_BASE=${HUB_PUBLIC_BASE%/}
KC_PUBLIC_BASE=${KC_PUBLIC_BASE%/}
KC_RELATIVE_PATH=${KC_RELATIVE_PATH}

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
HUB_DB_PASSWORD=${HUB_DB_PASSWORD}
KC_DB_PASSWORD=${KC_DB_PASSWORD}

HUB_OIDC_CLIENT_ID=${HUB_OIDC_CLIENT_ID}
HUB_SYSTEM_CLIENT_ID=${HUB_SYSTEM_CLIENT_ID}
HUB_SYSTEM_CLIENT_SECRET=${HUB_SYSTEM_CLIENT_SECRET}

EXTERNAL_KC_REALM=${EXTERNAL_KC_REALM}
KC_INTERNAL_URL=${KC_INTERNAL_URL}
EXTERNAL_KC_ISSUER=${EXTERNAL_KC_ISSUER}
EXTERNAL_KC_AUTH_SERVER_URL=${EXTERNAL_KC_AUTH_SERVER_URL}

HUB_REDIRECT_URI=${HUB_REDIRECT_URI}

KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}

REALM_ADMIN_USER=${REALM_ADMIN_USER}
REALM_ADMIN_PASSWORD=${REALM_ADMIN_PASSWORD}
REALM_ADMIN_TEMPORARY=${REALM_ADMIN_TEMP}
EOF
)

# compose.yml
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
      HUB_KEYCLOAK_PUBLIC_URL: \${KC_PUBLIC_BASE}
      HUB_KEYCLOAK_LOCAL_URL: \${KC_INTERNAL_URL}
      HUB_KEYCLOAK_REALM: \${EXTERNAL_KC_REALM}
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: \${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: \${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m
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
### Dateien ins LXC schreiben
### ---------------------------
info "Schreibe Dateien in den LXC"
pct_exec "$CTID" "mkdir -p '${APP_DIR}' '${DB_INIT_DIR}'"
pct_push_str "$CTID" "${DB_INIT_DIR}/initdb.sql" "$INITDB_SQL" 0600

if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  pct_exec "$CTID" "mkdir -p '${KC_IMPORT_DIR}'"
  pct_push_str "$CTID" "${KC_IMPORT_DIR}/realm.json" "$REALM_JSON" 0600
fi

pct_push_str "$CTID" "${APP_DIR}/compose.yml" "$COMPOSE_CONTENT" 0644
pct_push_str "$CTID" "${APP_DIR}/.env" "$ENV_CONTENT" 0600

### ---------------------------
### Start
### ---------------------------
info "Starte Stack (docker compose up -d)"
pct_exec "$CTID" "cd '${APP_DIR}' && docker compose --env-file .env -f compose.yml up -d"

### ---------------------------
### Summary
### ---------------------------
SUMMARY="Installation abgeschlossen.

CTID:            ${CTID}
Hostname:        ${HOSTNAME}
Variante:        $( [[ "$USE_EXTERNAL_KC" == "yes" ]] && echo "External Keycloak" || echo "Internal Keycloak" )

Hub lokal:       http://${BIND_IP}:${HUB_BIND_PORT}/
Hub Public:      ${HUB_PUBLIC_BASE%/}

Keycloak Public: ${KC_PUBLIC_BASE%/}
"

if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  SUMMARY+="
Keycloak lokal:  http://${BIND_IP}:${KC_BIND_PORT}${KC_RELATIVE_PATH}

Keycloak Admin (container env):
  user: admin
  pass: ${KEYCLOAK_ADMIN_PASSWORD}

Realm Admin (cryptomator):
  user: ${REALM_ADMIN_USER}
  pass: ${REALM_ADMIN_PASSWORD}
  temporary: ${REALM_ADMIN_TEMP}

Hinweis:
- Wenn du KC_PUBLIC_BASE oder KC_RELATIVE_PATH später änderst, entferne '--optimized' im Keycloak command.
"
else
  SUMMARY+="
External Keycloak:
  realm:  ${EXTERNAL_KC_REALM}
  issuer: ${EXTERNAL_KC_ISSUER}

Hinweis:
- Realm/Clients im externen Keycloak müssen korrekt existieren (cryptomatorhub, cryptomatorhub-system, cryptomator).
"
fi

ui_msg "Fertig" "$SUMMARY"
echo "$SUMMARY"
echo "Logs im LXC:"
echo "  pct exec ${CTID} -- bash -lc 'cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml logs -f'"
