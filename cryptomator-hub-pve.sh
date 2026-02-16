#!/usr/bin/env bash
# cryptomator-hub-pve.sh
#
# Proxmox VE helper-artiges Install-Script fuer Cryptomator Hub in Debian 12 LXC (Docker Compose)
#
# Varianten:
#  - Internal Keycloak: Postgres + Keycloak + Hub (Realm/Clients via realm.json Import)
#  - External Keycloak: Postgres + Hub (Keycloak existiert extern; Realm/Clients/Secrets extern bereitstellen)
#
# Fixes (gegen deine beobachteten Probleme):
#  - LXC Template wird dynamisch via `pveam available` ermittelt (kein Hardcode wie debian-12-standard_12.7-1_amd64.tar.zst)
#  - DNS-Check im LXC + optionaler DNS-Override bei DHCP (gegen "Temporary failure resolving")
#  - initdb.sql Permissions: 0644 + db-init dir 0755 (gegen "Permission denied" im Postgres Init)
#  - Postgres Healthcheck + hub depends_on service_healthy (gegen Race "Connection refused")
#  - Defaults werden bei ENTER sauber uebernommen (Image Defaults etc.)
#
# Ausfuehrung:
#  - Auf dem Proxmox Host als root
#
set -euo pipefail

### ---------------------------
### UI: Proxmox Helper Look & Feel (grau/blau)
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

ui_msg() { whiptail --title "${1:-Info}" --msgbox "${2:-}" 14 80; }
ui_yesno() { whiptail --title "${1:-Frage}" --yesno "${2:-}" 14 80; } # 0=yes 1=no

ui_input() { # ui_input "title" "text" "default" -> stdout ; ENTER => default
  local title="$1" text="$2" def="${3:-}"
  local out
  out="$(whiptail --title "$title" --inputbox "$text" 14 80 "$def" 3>&1 1>&2 2>&3)" || exit 1
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

lxc_net_check() {
  local ctid="$1"
  pct_exec "$ctid" "ip r >/dev/null 2>&1" || return 1
  pct_exec "$ctid" "getent ahosts deb.debian.org >/dev/null 2>&1" && return 0
  pct_exec "$ctid" "ping -c 1 -W 2 deb.debian.org >/dev/null 2>&1" && return 0
  return 1
}

### ---------------------------
### Preflight
### ---------------------------
[[ "$(id -u)" -eq 0 ]] || err "Bitte als root auf dem Proxmox VE Host ausfuehren."
need_cmd pveversion
need_cmd pct
need_cmd pveam
need_cmd pvesm
need_cmd openssl
need_cmd awk
need_cmd sed
need_cmd grep
ensure_whiptail

ui_msg "Cryptomator Hub Installer" \
"Dieses Script deployt Cryptomator Hub in einem Debian 12 LXC auf Proxmox VE.

Varianten:
- Internal Keycloak (Postgres + Keycloak + Hub)
- External Keycloak (Postgres + Hub, externer Keycloak)

Abbruch jederzeit mit ESC."

### ---------------------------
### Variante waehlen
### ---------------------------
MODE="$(ui_menu "Variante" "Welche Variante willst du deployen?" 14 80 5 \
  "internal" "Internal Keycloak (Postgres + Keycloak + Hub)" \
  "external" "External Keycloak (Postgres + Hub, Keycloak extern)")"

USE_EXTERNAL_KC="no"
[[ "$MODE" == "external" ]] && USE_EXTERNAL_KC="yes"

### ---------------------------
### LXC Basis
### ---------------------------
CTID="$(ui_input "LXC" "CTID (numerisch)\n\nHinweis: muss frei sein." "120")"
[[ "$CTID" =~ ^[0-9]+$ ]] || err "CTID muss numerisch sein."
if pct status "$CTID" >/dev/null 2>&1; then
  err "CTID $CTID existiert bereits. Bitte andere CTID waehlen oder Container entfernen."
fi

HOSTNAME="$(ui_input "LXC" "Hostname des LXC" "cryptomator-hub")"
TZ="$(ui_input "LXC" "Zeitzone im LXC" "Europe/Zurich")"

CORES="$(ui_input "Ressourcen" "CPU Cores" "2")"
RAM="$(ui_input "Ressourcen" "RAM (MB)" "2048")"
DISK_GB="$(ui_input "Ressourcen" "Disk (GB) – RootFS Groesse" "16")"
SWAP_MB="$(ui_input "Ressourcen" "Swap (MB)" "512")"
[[ "$CORES" =~ ^[0-9]+$ && "$RAM" =~ ^[0-9]+$ && "$DISK_GB" =~ ^[0-9]+$ && "$SWAP_MB" =~ ^[0-9]+$ ]] || err "Ressourcenwerte muessen numerisch sein."

### ---------------------------
### Storage
### ---------------------------
STORAGE_ROOTFS="$(ui_input "Storage" "Proxmox Storage fuer RootFS\n\nBeispiel: local-lvm, zfs, SSDStorage" "local-lvm")"

mapfile -t VZT_STORAGES < <(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1{print $1}' | sort -u)
if [[ "${#VZT_STORAGES[@]}" -eq 0 ]]; then
  TEMPLATE_STORAGE="$(ui_input "Templates" "Storage fuer LXC Templates (Content: vztmpl)\n\nHinweis: Oft 'local'." "local")"
else
  MENU_ITEMS=()
  for s in "${VZT_STORAGES[@]}"; do MENU_ITEMS+=("$s" "Storage mit vztmpl"); done
  TEMPLATE_STORAGE="$(ui_menu "Templates" "Waehle Storage fuer LXC Templates (vztmpl)" 14 80 6 "${MENU_ITEMS[@]}")"
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
DNS_OVERRIDE=""

if [[ "$USE_DHCP" == "no" ]]; then
  IP_CIDR="$(ui_input "Netzwerk" "Statische IP inkl. CIDR (z.B. 192.168.1.50/24)" "")"
  GATEWAY="$(ui_input "Netzwerk" "Gateway (z.B. 192.168.1.1)" "")"
  DNS_SERVER="$(ui_input "Netzwerk" "DNS Server (z.B. 1.1.1.1)" "1.1.1.1")"
  [[ -n "$IP_CIDR" && -n "$GATEWAY" ]] || err "Fuer statische IP muessen IP_CIDR und GATEWAY gesetzt sein."
else
  DNS_OVERRIDE="$(ui_input "Netzwerk" "DNS Override (optional)\n\nLeer lassen = DHCP/DHCPv6 verwenden.\nBei Problemen: z.B. 1.1.1.1 oder 9.9.9.9" "")"
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

if ui_yesno "Ports" "Ports oeffentlich binden (0.0.0.0) statt nur localhost?\n\nEmpfehlung: Nein (Reverse Proxy verwenden)."; then
  BIND_IP="0.0.0.0"
else
  BIND_IP="127.0.0.1"
fi

POSTGRES_IMAGE="$(ui_input "Images" "Postgres Image\n\nDefault wird bei ENTER uebernommen." "postgres:14-alpine")"
HUB_IMAGE="$(ui_input "Images" "Hub Image\n\nDefault wird bei ENTER uebernommen." "ghcr.io/cryptomator/hub:stable")"
validate_image "$POSTGRES_IMAGE" "Postgres Image"
validate_image "$HUB_IMAGE" "Hub Image"

KEYCLOAK_IMAGE="ghcr.io/cryptomator/keycloak:26.5.3"
if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  KEYCLOAK_IMAGE="$(ui_input "Images" "Keycloak Image\n\nDefault wird bei ENTER uebernommen." "ghcr.io/cryptomator/keycloak:26.5.3")"
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
  EXTERNAL_KC_ISSUER="$(ui_input "External Keycloak" "OIDC Issuer (QUARKUS_OIDC_TOKEN_ISSUER)\n\nBeispiel: ${EXTERNAL_KC_ISSUER_DEFAULT}" "$EXTERNAL_KC_ISSUER_DEFAULT")"
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
### Template ermitteln + downloaden (kein Hardcode)
### ---------------------------
info "Aktualisiere Template-Katalog (pveam update)"
pveam update >/dev/null

if ! pvesm status --content vztmpl 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$TEMPLATE_STORAGE"; then
  err "Der gewaehlte Template-Storage '$TEMPLATE_STORAGE' unterstuetzt kein 'vztmpl'. Bitte einen Storage mit Content 'vztmpl' waehlen (z.B. local)."
fi

TEMPLATE="$(pveam available --section system 2>/dev/null \
  | awk '{print $2}' \
  | grep -E '^debian-12-standard_.*_amd64\.tar\.zst$' \
  | sort -V \
  | tail -n 1)"

[[ -n "${TEMPLATE:-}" ]] || err "Konnte kein Debian-12-Template via 'pveam available' finden. Pruefe Internet/DNS/Repos."

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
else
  if [[ -n "$DNS_OVERRIDE" ]]; then
    pct set "$CTID" --nameserver "$DNS_OVERRIDE"
  fi
fi

info "Starte LXC CT $CTID"
pct start "$CTID"
sleep 6

if ! lxc_net_check "$CTID"; then
  if [[ -n "${DNS_OVERRIDE:-}" ]]; then
    ui_msg "Netzwerk/DNS Problem" \
"Der Container kann 'deb.debian.org' nicht aufloesen (trotz DNS Override: ${DNS_OVERRIDE}).

Pruefe:
- DHCP/Gateway
- VLAN/Firewall
- DNS im Netzwerk

Tipp:
pct exec ${CTID} -- cat /etc/resolv.conf"
    err "DNS/Netzwerk im LXC nicht funktional (trotz DNS Override)."
  fi

  ui_msg "Netzwerk/DNS Problem" \
"Der Container kann 'deb.debian.org' nicht aufloesen.
Das fuehrt spaeter zu Fehlern wie:
\"Temporary failure resolving 'deb.debian.org'\"

Setze jetzt einen DNS Override (empfohlen: 1.1.1.1)."

  DNS_OVERRIDE="$(ui_input "DNS Override" "DNS Server setzen (z.B. 1.1.1.1)\n\nLeer lassen = Abbruch" "1.1.1.1")"
  [[ -n "$DNS_OVERRIDE" ]] || err "Abbruch: DNS Override nicht gesetzt und DNS ist defekt."

  pct set "$CTID" --nameserver "$DNS_OVERRIDE"
  pct restart "$CTID"
  sleep 6

  if ! lxc_net_check "$CTID"; then
    ui_msg "Netzwerk/DNS Problem" \
"Trotz DNS Override (${DNS_OVERRIDE}) kann der Container 'deb.debian.org' nicht aufloesen.

Bitte manuell pruefen:
- pct exec ${CTID} -- cat /etc/resolv.conf
- pct exec ${CTID} -- ip r
- Routing/Firewall/VLAN"
    err "DNS/Netzwerk im LXC nicht funktional (nach DNS Override)."
  fi
fi

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
pct_exec "$CTID" "chmod 755 '${APP_DIR}' '${DB_INIT_DIR}'"
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

### initdb.sql (WICHTIG: Permissions 0644, sonst Postgres "Permission denied")
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

### realm.json (nur internal)
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

### .env
ENV_CONTENT=$(cat <<EOF
# Cryptomator Hub deployment (.env)
# WICHTIG: Diese Datei enthaelt Secrets. Nicht in Git einchecken.

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

### compose.yml mit Healthchecks (Postgres ready) + depends_on condition
if [[ "$USE_EXTERNAL_KC" == "yes" ]]; then
  COMPOSE_CONTENT=$(cat <<'EOF'
services:
  postgres:
    image: ${POSTGRES_IMAGE}
    volumes:
      - /opt/cryptomator-hub/data/db-init:/docker-entrypoint-initdb.d
      - /opt/cryptomator-hub/data/db-data:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 30

  hub:
    image: ${HUB_IMAGE}
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "${BIND_IP}:${HUB_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      HUB_PUBLIC_ROOT_PATH: /
      HUB_KEYCLOAK_PUBLIC_URL: ${KC_PUBLIC_BASE}
      HUB_KEYCLOAK_LOCAL_URL: ${KC_INTERNAL_URL}
      HUB_KEYCLOAK_REALM: ${EXTERNAL_KC_REALM}
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: ${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: ${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m
      HUB_KEYCLOAK_OIDC_CRYPTOMATOR_CLIENT_ID: cryptomator

      QUARKUS_OIDC_AUTH_SERVER_URL: ${EXTERNAL_KC_AUTH_SERVER_URL}
      QUARKUS_OIDC_TOKEN_ISSUER: ${EXTERNAL_KC_ISSUER}
      QUARKUS_OIDC_CLIENT_ID: ${HUB_OIDC_CLIENT_ID}

      QUARKUS_DATASOURCE_JDBC_URL: jdbc:postgresql://postgres:5432/hub
      QUARKUS_DATASOURCE_USERNAME: hub
      QUARKUS_DATASOURCE_PASSWORD: ${HUB_DB_PASSWORD}
      QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING: "true"
EOF
)
else
  COMPOSE_CONTENT=$(cat <<'EOF'
services:
  postgres:
    image: ${POSTGRES_IMAGE}
    volumes:
      - /opt/cryptomator-hub/data/db-init:/docker-entrypoint-initdb.d
      - /opt/cryptomator-hub/data/db-data:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 30

  keycloak:
    image: ${KEYCLOAK_IMAGE}
    depends_on:
      postgres:
        condition: service_healthy
    command: start --optimized --import-realm
    volumes:
      - /opt/cryptomator-hub/data/kc-import:/opt/keycloak/data/import
    ports:
      - "${BIND_IP}:${KC_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN_USER}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
      KC_HEALTH_ENABLED: "true"
      KC_HTTP_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_RELATIVE_PATH: ${KC_RELATIVE_PATH}
      KC_HOSTNAME: ${KC_PUBLIC_BASE}
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:9000${KC_RELATIVE_PATH}/health/live >/dev/null 2>&1 || curl -fsS http://localhost:9000/kc/health/live >/dev/null 2>&1 || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 60

  hub:
    image: ${HUB_IMAGE}
    depends_on:
      postgres:
        condition: service_healthy
      keycloak:
        condition: service_healthy
    ports:
      - "${BIND_IP}:${HUB_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      HUB_PUBLIC_ROOT_PATH: /
      HUB_KEYCLOAK_PUBLIC_URL: ${KC_PUBLIC_BASE}
      HUB_KEYCLOAK_LOCAL_URL: http://keycloak:8080${KC_RELATIVE_PATH}
      HUB_KEYCLOAK_REALM: cryptomator
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: ${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: ${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m
      HUB_KEYCLOAK_OIDC_CRYPTOMATOR_CLIENT_ID: cryptomator

      QUARKUS_OIDC_AUTH_SERVER_URL: http://keycloak:8080${KC_RELATIVE_PATH}/realms/cryptomator
      QUARKUS_OIDC_TOKEN_ISSUER: ${KC_PUBLIC_BASE}/realms/cryptomator
      QUARKUS_OIDC_CLIENT_ID: ${HUB_OIDC_CLIENT_ID}

      QUARKUS_DATASOURCE_JDBC_URL: jdbc:postgresql://postgres:5432/hub
      QUARKUS_DATASOURCE_USERNAME: hub
      QUARKUS_DATASOURCE_PASSWORD: ${HUB_DB_PASSWORD}
      QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING: "true"
EOF
)
fi

### ---------------------------
### Dateien ins LXC schreiben
### ---------------------------
info "Schreibe Dateien in den LXC"

pct_exec "$CTID" "mkdir -p '${APP_DIR}' '${DB_INIT_DIR}' '${DB_DATA_DIR}'"
pct_exec "$CTID" "chmod 755 '${DB_INIT_DIR}'"

# initdb.sql muss fuer Postgres-Container lesbar sein (0644)
pct_push_str "$CTID" "${DB_INIT_DIR}/initdb.sql" "$INITDB_SQL" 0644

if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  pct_exec "$CTID" "mkdir -p '${KC_IMPORT_DIR}'"
  # 0644 ist hier ebenfalls robust (Keycloak-Container kann sicher lesen)
  pct_push_str "$CTID" "${KC_IMPORT_DIR}/realm.json" "$REALM_JSON" 0644
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

Hub bind:        ${BIND_IP}:${HUB_BIND_PORT} -> 8080
Hub Public:      ${HUB_PUBLIC_BASE%/}

Keycloak Public: ${KC_PUBLIC_BASE%/}
"

if [[ "$BIND_IP" == "127.0.0.1" ]]; then
  SUMMARY+="
Hinweis:
- Ports sind nur lokal (127.0.0.1) gebunden.
- Externer Zugriff typischerweise via Reverse Proxy (443) auf ${BIND_IP}:${HUB_BIND_PORT}.
"
fi

if [[ "$USE_EXTERNAL_KC" == "no" ]]; then
  SUMMARY+="
Keycloak bind:   ${BIND_IP}:${KC_BIND_PORT} -> 8080
Keycloak Path:   ${KC_RELATIVE_PATH}

Keycloak Admin (container env):
  user: admin
  pass: ${KEYCLOAK_ADMIN_PASSWORD}

Realm Admin (cryptomator):
  user: ${REALM_ADMIN_USER}
  pass: ${REALM_ADMIN_PASSWORD}
  temporary: ${REALM_ADMIN_TEMP}

Hinweis:
- Wenn du KC_PUBLIC_BASE oder KC_RELATIVE_PATH spaeter aenderst, entferne '--optimized' im Keycloak command.
"
else
  SUMMARY+="
External Keycloak:
  realm:  ${EXTERNAL_KC_REALM}
  issuer: ${EXTERNAL_KC_ISSUER}

Hinweis:
- Realm/Clients/Secrets muessen im externen Keycloak korrekt existieren (cryptomatorhub, cryptomatorhub-system, cryptomator).
"
fi

ui_msg "Fertig" "$SUMMARY"
echo "$SUMMARY"
echo
echo "Troubleshooting (Logs):"
echo "  pct exec ${CTID} -- bash -lc 'cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml ps'"
echo "  pct exec ${CTID} -- bash -lc 'cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml logs -f --no-color'"
