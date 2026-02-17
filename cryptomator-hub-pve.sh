#!/usr/bin/env bash
# cryptomator-hub-pve.sh
# PVE Helper-artiges Install-Script für Cryptomator Hub (mit internem ODER externem Keycloak)
#
# Repo: https://github.com/Julian612/cryptomator-pve
#
# Voraussetzungen:
# - Proxmox VE Host
# - Internetzugang (Template-Download, Debian Pakete, Container Images)
#
# Hinweis zu Secrets:
# - Dieses Script schreibt Secrets in /opt/cryptomator-hub/.env im LXC.
# - Niemals ins Git einchecken.

set -Eeuo pipefail

############################################
# UI (whiptail) – Cursor & Look            #
############################################
export DEBIAN_FRONTEND=noninteractive
export NCURSES_NO_UTF8_ACS=1

# aktiver Cursor sichtbar (actentry)
export NEWT_COLORS='
root=white,blue
border=white,blue
window=white,blue
shadow=black,blue
title=white,blue
button=black,cyan
actbutton=black,white
checkbox=black,cyan
actcheckbox=black,white
entry=black,white
actentry=white,black
label=white,blue
listbox=black,white
actlistbox=black,cyan
textbox=white,blue
helpline=white,blue
roottext=white,blue
emptyscale=white,blue
fullscale=white,blue
disentry=black,white
compactbutton=black,cyan
'

cleanup() {
  tput cnorm >/dev/null 2>&1 || true
  # falls Spinner-FD offen bleibt
  exec 9>&- 2>/dev/null || true
}
trap cleanup EXIT
tput cnorm >/dev/null 2>&1 || true

############################################
# Helpers                                  #
############################################
die() { echo "ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Befehl fehlt: $1"; }

msgbox() { whiptail --title "${1:-Info}" --msgbox "${2:-}" 14 78; }
yesno()  { whiptail --title "${1:-Frage}" --yesno "${2:-}" 12 78; }

inputbox() {
  local title="$1" prompt="$2" def="${3:-}"
  tput cnorm >/dev/null 2>&1 || true
  whiptail --title "$title" --inputbox "$prompt" 12 78 "$def" 3>&1 1>&2 2>&3
}

passwordbox() {
  local title="$1" prompt="$2"
  tput cnorm >/dev/null 2>&1 || true
  whiptail --title "$title" --passwordbox "$prompt" 12 78 "" 3>&1 1>&2 2>&3
}

radiolist() {
  local title="$1" prompt="$2" height="${3:-12}" width="${4:-78}" listheight="${5:-6}"
  shift 5
  whiptail --title "$title" --radiolist "$prompt" "$height" "$width" "$listheight" "$@" 3>&1 1>&2 2>&3
}

menulist() {
  local title="$1" prompt="$2" height="${3:-20}" width="${4:-78}" listheight="${5:-10}"
  shift 5
  whiptail --title "$title" --menu "$prompt" "$height" "$width" "$listheight" "$@" 3>&1 1>&2 2>&3
}

# Spinner (Gauge) für längere Operationen
spinner_start() {
  local title="$1" msg="$2"
  _SPINNER_FIFO="$(mktemp -u /tmp/spinner_XXXXXX)"
  mkfifo "$_SPINNER_FIFO"
  whiptail --title "$title" --gauge "$msg" 8 78 0 < "$_SPINNER_FIFO" &
  _SPINNER_PID=$!
  exec 9>"$_SPINNER_FIFO"

  (
    s=0
    while kill -0 "$_SPINNER_PID" 2>/dev/null; do
      echo "$s" >&9
      s=$(( (s + 4) % 99 ))
      sleep 0.3
    done
  ) &
  _SPINNER_ANIM_PID=$!
}

spinner_stop() {
  local pid="${_SPINNER_PID:-}"
  local apid="${_SPINNER_ANIM_PID:-}"
  local fifo="${_SPINNER_FIFO:-}"

  echo "100" >&9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true

  [[ -n "$apid" ]] && kill "$apid" 2>/dev/null || true
  [[ -n "$pid"  ]] && wait "$pid"  2>/dev/null || true
  [[ -n "$apid" ]] && wait "$apid" 2>/dev/null || true
  [[ -n "$fifo" ]] && rm -f "$fifo" 2>/dev/null || true
}

is_int()   { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
rand_hex() { openssl rand -hex "${1:-16}"; }

############################################
# Preconditions                            #
############################################
need_cmd whiptail
need_cmd pveam
need_cmd pct
need_cmd pvesm
need_cmd pvesh
need_cmd awk
need_cmd openssl

if [[ "${EUID}" -ne 0 ]]; then
  die "Bitte als root auf dem Proxmox Host ausführen."
fi

############################################
# Storage-Auswahl                          #
############################################
pick_storage() {
  local menu_args=()
  while IFS= read -r stor; do
    [[ -n "$stor" ]] && menu_args+=("$stor" "LXC Template Storage")
  done < <(pvesm status -content vztmpl | awk 'NR>1 {print $1}')

  [[ ${#menu_args[@]} -gt 0 ]] || die "Kein Storage mit Content 'vztmpl' gefunden. Prüfe pvesm status."

  if [[ ${#menu_args[@]} -eq 2 ]]; then
    echo "${menu_args[0]}"
  else
    menulist "Storage" "Storage für LXC Template und Rootfs wählen:" 16 78 8 "${menu_args[@]}"
  fi
}

############################################
# Template                                 #
############################################
latest_debian12_template() {
  pveam available --section system 2>/dev/null \
    | awk '{print $2}' \
    | grep -E '^debian-12-standard_.*_amd64\.tar\.zst$' \
    | sort -V \
    | tail -n1
}

ensure_template() {
  local storage="$1" tmpl="$2"
  if ! pveam list "$storage" | awk '{print $1}' | grep -qx "$tmpl"; then
    msgbox "Template Download" \
"Debian Template nicht lokal vorhanden.\n\nLade herunter:\n${tmpl}\n\nStorage: ${storage}\n\nDies kann einige Minuten dauern…"
    spinner_start "Template Download" "Lade ${tmpl}…"
    pveam download "$storage" "$tmpl"
    local rc=$?
    spinner_stop
    [[ $rc -eq 0 ]] || die "Template Download fehlgeschlagen."
  fi
}

############################################
# next-free CTID                           #
############################################
next_free_ctid() {
  pvesh get /cluster/nextid 2>/dev/null || echo "100"
}

############################################
# LXC-IP ermitteln                         #
############################################
get_lxc_ip() {
  local ctid="$1" ip="" attempts=0
  while [[ -z "$ip" && $attempts -lt 20 ]]; do
    ip="$(pct exec "$ctid" -- hostname -I 2>/dev/null | awk '{print $1}' || true)"
    [[ -n "$ip" ]] && break
    sleep 2
    attempts=$(( attempts + 1 ))
  done
  echo "${ip:-<IP nicht ermittelbar>}"
}

############################################
# Inputs                                   #
############################################
BACKTITLE="Cryptomator Hub Installer (PVE Helper-artig)"

whiptail --backtitle "$BACKTITLE" --title "Cryptomator Hub" --msgbox \
"Dieses Script erstellt einen Debian LXC Container und deployt:\n\n\
  - Cryptomator Hub\n\
  - Postgres\n\
  - Optional: Keycloak (intern)\n\n\
Du kannst zwischen 'Standard' (Defaults) und 'Erweitert' wählen.\n\
Im Standard-Modus werden nur die wichtigsten Werte abgefragt." \
16 78

INSTALL_MODE="$(radiolist "Installationsmodus" "Modus wählen:" 12 78 2 \
  "standard"  "Standard  – sinnvolle Defaults, minimale Eingaben (empfohlen)" ON \
  "advanced"  "Erweitert – alle Parameter manuell konfigurieren" OFF \
)" || exit 1

# Defaults
DEFAULT_CTID="$(next_free_ctid)"
DEFAULT_HOSTNAME="cryptomator-hub"
DEFAULT_TZ="Europe/Zurich"
DEFAULT_CORES="2"
DEFAULT_RAM="2048"
DEFAULT_DISK="16"
DEFAULT_SWAP="512"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_BINDIP="0.0.0.0"
DEFAULT_KC_PORT="8081"
DEFAULT_HUB_PORT="8082"
DEFAULT_PG_IMAGE="postgres:14-alpine"
DEFAULT_HUB_IMAGE="ghcr.io/cryptomator/hub:stable"
DEFAULT_KC_IMAGE="ghcr.io/cryptomator/keycloak:26.5.3"
DEFAULT_REALM="cryptomator"
DEFAULT_REALM_ADMIN="admin"
DEFAULT_OIDC_CLIENT="cryptomatorhub"
DEFAULT_SYSTEM_CLIENT="cryptomatorhub-system"

NET_MODE="dhcp"
STATIC_IP="" STATIC_GW="" STATIC_DNS=""

external_warning_text=$'Extern bedeutet:\n\n- Realm/Clients/Mapper/Secrets manuell korrekt setzen\n- Häufige Fehler: 401/403, weisse UI, fehlende Rollen im Token\n\nWenn du nicht sehr genau weisst, was du tust: intern wählen.'

# Shared vars
CTID="" HOSTNAME="" TZ="" CORES="" RAM="" DISK="" SWAP="" BRIDGE=""
BIND_IP="" KC_BIND_PORT="" HUB_BIND_PORT=""
POSTGRES_IMAGE="" HUB_IMAGE="" KEYCLOAK_IMAGE=""
KC_MODE=""
HUB_PUBLIC_BASE="" KC_PUBLIC_BASE=""
REALM_NAME="" REALM_ADMIN_USER="" REALM_ADMIN_PW="" REALM_ADMIN_TEMP=""
HUB_OIDC_CLIENT_ID="" HUB_SYSTEM_CLIENT_ID="" HUB_REDIRECT_URI=""
HUB_SYSTEM_CLIENT_SECRET=""

if [[ "$INSTALL_MODE" == "standard" ]]; then
  CTID="$(inputbox "Container" "CTID (nächste freie ID vorausgefüllt):" "$DEFAULT_CTID")" || exit 1
  is_int "$CTID" || die "CTID muss numerisch sein."

  HOSTNAME="$(inputbox "Container" "LXC Hostname:" "$DEFAULT_HOSTNAME")" || exit 1

  KC_MODE="$(radiolist "Keycloak" "Keycloak Deployment:" 14 78 2 \
    "internal" "Keycloak im selben LXC deployen (empfohlen)" ON \
    "external" "Externen Keycloak verwenden (aufwendig, manuelle Konfiguration)" OFF \
  )" || exit 1

  if [[ "$KC_MODE" == "external" ]]; then
    msgbox "Warnung (Externer Keycloak)" "$external_warning_text"
    yesno "Bestätigung" "Externen Keycloak wirklich verwenden?" || { echo "Abgebrochen."; exit 0; }
  fi

  # Ports (auch im Standard-Modus)
  BIND_IP="$DEFAULT_BINDIP"
  KC_BIND_PORT="$(inputbox "Ports" "Keycloak Host-Port (→ Container 8080):" "$DEFAULT_KC_PORT")" || exit 1
  is_int "$KC_BIND_PORT" || die "Keycloak Port muss numerisch sein."
  HUB_BIND_PORT="$(inputbox "Ports" "Hub Host-Port (→ Container 8080):" "$DEFAULT_HUB_PORT")" || exit 1
  is_int "$HUB_BIND_PORT" || die "Hub Port muss numerisch sein."
  [[ "$KC_BIND_PORT" != "$HUB_BIND_PORT" ]] || die "Keycloak Port und Hub Port dürfen nicht identisch sein."

  HUB_PUBLIC_BASE="$(inputbox "URLs" "Hub Public Base URL\n(z.B. https://cryptomator.example.tld):" "https://hub.example.tld")" || exit 1
  KC_PUBLIC_BASE="$(inputbox "URLs" "Keycloak Public Base URL\n(OHNE /kc, z.B. https://auth.example.tld):" "https://auth.example.tld")" || exit 1

  REALM_ADMIN_PW="$(passwordbox "Realm" "Initiales Realm-Admin Passwort:")" || exit 1
  [[ -n "$REALM_ADMIN_PW" ]] || die "Realm-Admin Passwort darf nicht leer sein."

  TZ="$DEFAULT_TZ"
  CORES="$DEFAULT_CORES"
  RAM="$DEFAULT_RAM"
  DISK="$DEFAULT_DISK"
  SWAP="$DEFAULT_SWAP"
  BRIDGE="$DEFAULT_BRIDGE"

  POSTGRES_IMAGE="$DEFAULT_PG_IMAGE"
  HUB_IMAGE="$DEFAULT_HUB_IMAGE"
  KEYCLOAK_IMAGE="$DEFAULT_KC_IMAGE"

  HUB_OIDC_CLIENT_ID="$DEFAULT_OIDC_CLIENT"
  HUB_SYSTEM_CLIENT_ID="$DEFAULT_SYSTEM_CLIENT"
  HUB_REDIRECT_URI="${HUB_PUBLIC_BASE}/*"

  REALM_NAME="$DEFAULT_REALM"
  REALM_ADMIN_USER="$DEFAULT_REALM_ADMIN"
  REALM_ADMIN_TEMP="true"
else
  CTID="$(inputbox "Container" "CTID (numerisch):" "$DEFAULT_CTID")" || exit 1
  is_int "$CTID" || die "CTID muss numerisch sein."

  HOSTNAME="$(inputbox "Container" "LXC Hostname:" "$DEFAULT_HOSTNAME")" || exit 1
  TZ="$(inputbox "Container" "Zeitzone im LXC:" "$DEFAULT_TZ")" || exit 1

  KC_MODE="$(radiolist "Keycloak" "Keycloak Deployment auswählen:" 14 78 2 \
    "internal" "Keycloak im selben LXC deployen (empfohlen)" ON \
    "external" "Externen Keycloak verwenden (aufwendig, manuelle Konfiguration)" OFF \
  )" || exit 1

  if [[ "$KC_MODE" == "external" ]]; then
    msgbox "Warnung (Externer Keycloak)" "$external_warning_text"
    yesno "Bestätigung" "Externen Keycloak wirklich verwenden?" || { echo "Abgebrochen."; exit 0; }
  fi

  CORES="$(inputbox "Ressourcen" "CPU Cores:" "$DEFAULT_CORES")" || exit 1
  is_int "$CORES" || die "CPU Cores muss numerisch sein."
  RAM="$(inputbox "Ressourcen" "RAM (MB):" "$DEFAULT_RAM")" || exit 1
  is_int "$RAM" || die "RAM muss numerisch sein."
  DISK="$(inputbox "Ressourcen" "Disk (GB):" "$DEFAULT_DISK")" || exit 1
  is_int "$DISK" || die "Disk muss numerisch sein."
  SWAP="$(inputbox "Ressourcen" "Swap (MB):" "$DEFAULT_SWAP")" || exit 1
  is_int "$SWAP" || die "Swap muss numerisch sein."

  BRIDGE="$(inputbox "Netzwerk" "Network Bridge:" "$DEFAULT_BRIDGE")" || exit 1

  NET_MODE="$(radiolist "Netzwerk" "Netzwerk-Konfiguration:" 12 78 2 \
    "dhcp"   "DHCP (empfohlen)" ON \
    "static" "Statisch – IP/GW/DNS manuell eingeben" OFF \
  )" || exit 1

  if [[ "$NET_MODE" == "static" ]]; then
    STATIC_IP="$(inputbox "Netzwerk" "Statische IP mit Prefix (z.B. 192.168.1.50/24):" "")" || exit 1
    [[ -n "$STATIC_IP" ]] || die "Statische IP darf nicht leer sein."
    STATIC_GW="$(inputbox "Netzwerk" "Gateway (z.B. 192.168.1.1):" "")" || exit 1
    [[ -n "$STATIC_GW" ]] || die "Gateway darf nicht leer sein."
    STATIC_DNS="$(inputbox "Netzwerk" "DNS Server (z.B. 1.1.1.1):" "1.1.1.1")" || exit 1
  fi

  BIND_IP="$(inputbox "Ports" "Bind IP\n(0.0.0.0 = LAN, 127.0.0.1 = nur lokal):" "$DEFAULT_BINDIP")" || exit 1
  KC_BIND_PORT="$(inputbox "Ports" "Keycloak Host-Port (→ Container 8080):" "$DEFAULT_KC_PORT")" || exit 1
  is_int "$KC_BIND_PORT" || die "Keycloak Port muss numerisch sein."
  HUB_BIND_PORT="$(inputbox "Ports" "Hub Host-Port (→ Container 8080):" "$DEFAULT_HUB_PORT")" || exit 1
  is_int "$HUB_BIND_PORT" || die "Hub Port muss numerisch sein."
  [[ "$KC_BIND_PORT" != "$HUB_BIND_PORT" ]] || die "Keycloak Port und Hub Port dürfen nicht identisch sein."

  HUB_PUBLIC_BASE="$(inputbox "URLs" "Hub Public Base URL\n(z.B. https://cryptomator.example.tld):" "https://hub.example.tld")" || exit 1
  KC_PUBLIC_BASE="$(inputbox "URLs" "Keycloak Public Base URL\n(OHNE /kc, z.B. https://auth.example.tld):" "https://auth.example.tld")" || exit 1

  POSTGRES_IMAGE="$(inputbox "Images" "Postgres Image:" "$DEFAULT_PG_IMAGE")" || exit 1
  [[ -n "$POSTGRES_IMAGE" ]] || POSTGRES_IMAGE="$DEFAULT_PG_IMAGE"
  HUB_IMAGE="$(inputbox "Images" "Hub Image:" "$DEFAULT_HUB_IMAGE")" || exit 1
  [[ -n "$HUB_IMAGE" ]] || HUB_IMAGE="$DEFAULT_HUB_IMAGE"
  KEYCLOAK_IMAGE="$(inputbox "Images" "Keycloak Image:" "$DEFAULT_KC_IMAGE")" || exit 1
  [[ -n "$KEYCLOAK_IMAGE" ]] || KEYCLOAK_IMAGE="$DEFAULT_KC_IMAGE"

  HUB_OIDC_CLIENT_ID="$(inputbox "OIDC" "OIDC Client ID (Hub) in Keycloak:" "$DEFAULT_OIDC_CLIENT")" || exit 1
  HUB_SYSTEM_CLIENT_ID="$(inputbox "OIDC" "System Client ID für Hub-Sync:" "$DEFAULT_SYSTEM_CLIENT")" || exit 1
  HUB_REDIRECT_URI="$(inputbox "OIDC" "Hub Redirect URI:" "${HUB_PUBLIC_BASE}/*")" || exit 1

  REALM_NAME="$(inputbox "Realm" "Realm Name:" "$DEFAULT_REALM")" || exit 1
  REALM_ADMIN_USER="$(inputbox "Realm" "Initialer Realm-Admin Username:" "$DEFAULT_REALM_ADMIN")" || exit 1
  REALM_ADMIN_PW="$(passwordbox "Realm" "Initiales Realm-Admin Passwort:")" || exit 1
  [[ -n "$REALM_ADMIN_PW" ]] || die "Realm-Admin Passwort darf nicht leer sein."

  REALM_ADMIN_TEMP="true"
  if yesno "Realm" "Realm-Admin Passwort bei erstem Login ändern erzwingen (temporary)?"; then
    REALM_ADMIN_TEMP="true"
  else
    REALM_ADMIN_TEMP="false"
  fi
fi

############################################
# Externer Keycloak: Client Secret         #
############################################
if [[ "$KC_MODE" == "external" ]]; then
  msgbox "Extern (Pflichtangabe)" \
"Du musst das Client Secret für den System-Client im externen Keycloak kennen.\n\nClient: ${HUB_SYSTEM_CLIENT_ID}\nRealm:  ${REALM_NAME}"
  HUB_SYSTEM_CLIENT_SECRET="$(passwordbox "External Keycloak" "Client Secret für ${HUB_SYSTEM_CLIENT_ID}:")" || exit 1
  [[ -n "$HUB_SYSTEM_CLIENT_SECRET" ]] || die "Client Secret darf nicht leer sein (external keycloak)."
fi

############################################
# Zusammenfassung                          #
############################################
yesno "Bestätigung" \
"Folgende Konfiguration wird installiert:\n\n\
CTID:      ${CTID}\n\
Hostname:  ${HOSTNAME}\n\
Keycloak:  ${KC_MODE}\n\
Hub URL:   ${HUB_PUBLIC_BASE}\n\
KC URL:    ${KC_PUBLIC_BASE}\n\
Realm:     ${REALM_NAME}\n\
Ports:     Hub=${HUB_BIND_PORT}  Keycloak=${KC_BIND_PORT}\n\n\
Fortfahren?" || { echo "Abgebrochen."; exit 0; }

############################################
# Storage / Template                       #
############################################
STORAGE="$(pick_storage)"
TEMPLATE="$(latest_debian12_template)"
[[ -n "$TEMPLATE" ]] || die "Konnte kein debian-12-standard Template in 'pveam available' finden."
ensure_template "$STORAGE" "$TEMPLATE"

############################################
# LXC erstellen                            #
############################################
if pct status "$CTID" >/dev/null 2>&1; then
  die "CTID $CTID existiert bereits. Bitte einen freien CTID wählen oder den Container zuerst löschen."
fi

LXC_ROOT_PW="$(rand_hex 8)"

if [[ "$NET_MODE" == "static" ]]; then
  NET0="name=eth0,bridge=${BRIDGE},ip=${STATIC_IP},gw=${STATIC_GW},type=veth"
  PCT_CREATE_ARGS=(
    --hostname  "$HOSTNAME"
    --cores     "$CORES"
    --memory    "$RAM"
    --swap      "$SWAP"
    --rootfs    "${STORAGE}:${DISK}"
    --net0      "$NET0"
    --nameserver "$STATIC_DNS"
    --features  "nesting=1,keyctl=1"
    --unprivileged 1
    --timezone  "$TZ"
    --password  "$LXC_ROOT_PW"
    --onboot    1
  )
else
  NET0="name=eth0,bridge=${BRIDGE},ip=dhcp,type=veth"
  PCT_CREATE_ARGS=(
    --hostname  "$HOSTNAME"
    --cores     "$CORES"
    --memory    "$RAM"
    --swap      "$SWAP"
    --rootfs    "${STORAGE}:${DISK}"
    --net0      "$NET0"
    --features  "nesting=1,keyctl=1"
    --unprivileged 1
    --timezone  "$TZ"
    --password  "$LXC_ROOT_PW"
    --onboot    1
  )
fi

spinner_start "LXC" "Erstelle Container ${CTID} (${HOSTNAME})…"
pct create "$CTID" "${STORAGE}:vztmpl/${TEMPLATE}" "${PCT_CREATE_ARGS[@]}"
spinner_stop

pct start "$CTID" || die "pct start fehlgeschlagen."

spinner_start "LXC" "Warte auf Container-Start…"
_ct_ready=0
for _i in $(seq 1 30); do
  if pct exec "$CTID" -- true 2>/dev/null; then
    _ct_ready=1
    break
  fi
  sleep 2
done
spinner_stop
[[ $_ct_ready -eq 1 ]] || die "Container antwortet nach 60s nicht. Prüfe: pct status $CTID"

############################################
# exec_ct                                  #
############################################
exec_ct() {
  pct exec "$CTID" -- bash -lc "$1"
}

############################################
# Bootstrap im Container                   #
############################################
if ! exec_ct "getent hosts deb.debian.org >/dev/null 2>&1"; then
  msgbox "Netz/DNS Problem" \
"Im Container kann 'deb.debian.org' nicht aufgelöst werden.\n\n\
Das ist kein Script-Fehler, sondern ein DNS/Netzwerk-Problem im LXC.\n\n\
Prüfen im Container (pct enter ${CTID}):\n\
  - cat /etc/resolv.conf\n\
  - ip r\n\
  - ping 1.1.1.1\n\n\
Container wird gestoppt. Problem beheben und Script erneut starten."
  pct stop "$CTID" || true
  exit 1
fi

spinner_start "Bootstrap" "apt-get update…"
exec_ct "apt-get update -y"
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "apt-get update fehlgeschlagen."

spinner_start "Bootstrap" "Installiere Docker (ca. 1-2 Minuten)…"
exec_ct "apt-get install -y ca-certificates curl gnupg docker.io docker-compose-plugin"
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "Docker Installation fehlgeschlagen."

spinner_start "Bootstrap" "Starte Docker Service…"
exec_ct "systemctl enable --now docker"
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "Docker Service konnte nicht gestartet werden."

exec_ct "mkdir -p /opt/cryptomator-hub/data/db-init /opt/cryptomator-hub/data/db-data /opt/cryptomator-hub/kc-import" \
  || die "Verzeichnisse konnten nicht angelegt werden."

############################################
# Secrets                                 #
############################################
POSTGRES_PASSWORD="$(rand_hex 24)"
HUB_DB_PASSWORD="$(rand_hex 24)"
KC_DB_PASSWORD="$(rand_hex 24)"

if [[ "$KC_MODE" == "internal" ]]; then
  HUB_SYSTEM_CLIENT_SECRET="$(rand_hex 24)"
fi

# CSP: connect-src muss Keycloak erlauben (sonst weisse UI)
CSP="default-src 'self'; connect-src 'self' api.cryptomator.org ${KC_PUBLIC_BASE}; object-src 'none'; child-src 'self'; img-src * data:; frame-ancestors 'none'"

############################################
# initdb.sql                              #
############################################
exec_ct "cat > /opt/cryptomator-hub/data/db-init/initdb.sql <<'EOSQL'
CREATE USER keycloak WITH ENCRYPTED PASSWORD '${KC_DB_PASSWORD}';
CREATE DATABASE keycloak WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

CREATE USER hub WITH ENCRYPTED PASSWORD '${HUB_DB_PASSWORD}';
CREATE DATABASE hub WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE hub TO hub;
EOSQL
chmod 644 /opt/cryptomator-hub/data/db-init/initdb.sql" \
  || die "initdb.sql konnte nicht geschrieben werden."

############################################
# .env (CSP MUSS gequotet sein)           #
############################################
KC_DB_PW_VALUE=""
USE_EXTERNAL_VALUE="no"
if [[ "$KC_MODE" == "internal" ]]; then
  KC_DB_PW_VALUE="${KC_DB_PASSWORD}"
else
  USE_EXTERNAL_VALUE="yes"
fi

pct exec "$CTID" -- tee /opt/cryptomator-hub/.env > /dev/null <<ENV
# Cryptomator Hub deployment (.env)
# WICHTIG: Diese Datei enthaelt Secrets. Nicht in Git einchecken.

USE_EXTERNAL_KC=${USE_EXTERNAL_VALUE}

POSTGRES_IMAGE=${POSTGRES_IMAGE}
HUB_IMAGE=${HUB_IMAGE}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE}

BIND_IP=${BIND_IP}
KC_BIND_PORT=${KC_BIND_PORT}
HUB_BIND_PORT=${HUB_BIND_PORT}

HUB_PUBLIC_BASE=${HUB_PUBLIC_BASE}
KC_PUBLIC_BASE=${KC_PUBLIC_BASE}

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
HUB_DB_PASSWORD=${HUB_DB_PASSWORD}
KC_DB_PASSWORD=${KC_DB_PW_VALUE}

HUB_OIDC_CLIENT_ID=${HUB_OIDC_CLIENT_ID}
HUB_SYSTEM_CLIENT_ID=${HUB_SYSTEM_CLIENT_ID}
HUB_SYSTEM_CLIENT_SECRET=${HUB_SYSTEM_CLIENT_SECRET}

EXTERNAL_KC_REALM=${REALM_NAME}
KC_INTERNAL_URL=${KC_PUBLIC_BASE}
EXTERNAL_KC_ISSUER=${KC_PUBLIC_BASE}/realms/${REALM_NAME}
EXTERNAL_KC_AUTH_SERVER_URL=${KC_PUBLIC_BASE}/realms/${REALM_NAME}

HUB_REDIRECT_URI=${HUB_REDIRECT_URI}

REALM_ADMIN_USER=${REALM_ADMIN_USER}
REALM_ADMIN_PASSWORD=${REALM_ADMIN_PW}
REALM_ADMIN_TEMPORARY=${REALM_ADMIN_TEMP}

QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE="${CSP}"
ENV
[[ $? -eq 0 ]] || die ".env konnte nicht geschrieben werden."

############################################
# realm.json (nur intern)                  #
# - claim.name für client roles: konkrete  #
#   Client-ID, nicht ${client_id}          #
############################################
if [[ "$KC_MODE" == "internal" ]]; then
  pct exec "$CTID" -- tee /opt/cryptomator-hub/kc-import/realm.json > /dev/null <<REALM
{
  "id": "${REALM_NAME}",
  "realm": "${REALM_NAME}",
  "displayName": "Cryptomator Hub",
  "enabled": true,
  "sslRequired": "external",
  "roles": {
    "realm": [
      {"name":"user","description":"User","composite":false},
      {"name":"create-vaults","description":"Can create vaults","composite":false},
      {
        "name":"admin",
        "description":"Administrator",
        "composite": true,
        "composites": {
          "realm": ["user","create-vaults"],
          "client": {"realm-management": ["realm-admin"]}
        }
      }
    ]
  },
  "users": [
    {
      "username": "${REALM_ADMIN_USER}",
      "enabled": true,
      "credentials": [
        {"type":"password","value":"${REALM_ADMIN_PW}","temporary": ${REALM_ADMIN_TEMP}}
      ],
      "realmRoles": ["admin"]
    }
  ],
  "clients": [
    {
      "clientId": "${HUB_OIDC_CLIENT_ID}",
      "publicClient": true,
      "name": "Cryptomator Hub",
      "enabled": true,
      "redirectUris": ["${HUB_REDIRECT_URI}"],
      "webOrigins": ["+"],
      "protocol": "openid-connect",
      "attributes": {"pkce.code.challenge.method":"S256"},
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
            "claim.name": "resource_access.${HUB_OIDC_CLIENT_ID}.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        }
      ]
    },
    {
      "clientId": "cryptomator",
      "publicClient": true,
      "name": "Cryptomator App",
      "enabled": true,
      "redirectUris": [
        "http://127.0.0.1/*",
        "org.cryptomator.ios:/hub/auth",
        "org.cryptomator.android:/hub/auth"
      ],
      "webOrigins": ["+"],
      "protocol": "openid-connect",
      "attributes": {"pkce.code.challenge.method":"S256"}
    },
    {
      "clientId": "${HUB_SYSTEM_CLIENT_ID}",
      "serviceAccountsEnabled": true,
      "publicClient": false,
      "name": "Cryptomator Hub System",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "${HUB_SYSTEM_CLIENT_SECRET}",
      "standardFlowEnabled": false,
      "directAccessGrantsEnabled": false
    }
  ]
}
REALM
  [[ $? -eq 0 ]] || die "realm.json konnte nicht geschrieben werden."
fi

############################################
# compose.yml                              #
# Keycloak ohne /kc (Root)                 #
############################################
if [[ "$KC_MODE" == "internal" ]]; then
  pct exec "$CTID" -- tee /opt/cryptomator-hub/compose.yml > /dev/null <<'COMPOSE'
services:
  postgres:
    image: ${POSTGRES_IMAGE}
    volumes:
      - /opt/cryptomator-hub/data/db-init:/docker-entrypoint-initdb.d:ro
      - /opt/cryptomator-hub/data/db-data:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 3s
      retries: 20

  keycloak:
    image: ${KEYCLOAK_IMAGE}
    depends_on:
      postgres:
        condition: service_healthy
    command: start --optimized --import-realm
    volumes:
      - /opt/cryptomator-hub/kc-import:/opt/keycloak/data/import:ro
    ports:
      - "${BIND_IP}:${KC_BIND_PORT}:8080"
    restart: unless-stopped
    environment:
      KEYCLOAK_ADMIN: ${REALM_ADMIN_USER}
      KEYCLOAK_ADMIN_PASSWORD: ${REALM_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
      KC_HEALTH_ENABLED: "true"
      KC_HTTP_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_RELATIVE_PATH: /
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:9000/health/live >/dev/null || exit 1"]
      interval: 15s
      timeout: 3s
      retries: 30

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
      HUB_KEYCLOAK_LOCAL_URL: http://keycloak:8080
      HUB_KEYCLOAK_REALM: ${EXTERNAL_KC_REALM}
      HUB_KEYCLOAK_SYSTEM_CLIENT_ID: ${HUB_SYSTEM_CLIENT_ID}
      HUB_KEYCLOAK_SYSTEM_CLIENT_SECRET: ${HUB_SYSTEM_CLIENT_SECRET}
      HUB_KEYCLOAK_SYNCER_PERIOD: 5m
      HUB_KEYCLOAK_OIDC_CRYPTOMATOR_CLIENT_ID: cryptomator
      QUARKUS_OIDC_AUTH_SERVER_URL: http://keycloak:8080/realms/${EXTERNAL_KC_REALM}
      QUARKUS_OIDC_TOKEN_ISSUER: ${KC_PUBLIC_BASE}/realms/${EXTERNAL_KC_REALM}
      QUARKUS_OIDC_CLIENT_ID: ${HUB_OIDC_CLIENT_ID}
      QUARKUS_DATASOURCE_JDBC_URL: jdbc:postgresql://postgres:5432/hub
      QUARKUS_DATASOURCE_USERNAME: hub
      QUARKUS_DATASOURCE_PASSWORD: ${HUB_DB_PASSWORD}
      QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING: "true"
      QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE: "${QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE}"
COMPOSE
  [[ $? -eq 0 ]] || die "compose.yml (intern) konnte nicht geschrieben werden."
else
  pct exec "$CTID" -- tee /opt/cryptomator-hub/compose.yml > /dev/null <<'COMPOSE'
services:
  postgres:
    image: ${POSTGRES_IMAGE}
    volumes:
      - /opt/cryptomator-hub/data/db-init:/docker-entrypoint-initdb.d:ro
      - /opt/cryptomator-hub/data/db-data:/var/lib/postgresql/data
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: --encoding=UTF8
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 3s
      retries: 20

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
      QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE: "${QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE}"
COMPOSE
  [[ $? -eq 0 ]] || die "compose.yml (extern) konnte nicht geschrieben werden."
fi

############################################
# Deploy                                   #
############################################
spinner_start "Deploy" "Starte Docker Compose Stack (Pull kann dauern)…"
exec_ct "cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml up -d"
_deploy_rc=$?
spinner_stop
[[ $_deploy_rc -eq 0 ]] || die "docker compose up fehlgeschlagen. Prüfe: pct enter ${CTID} → cd /opt/cryptomator-hub && docker compose logs"

############################################
# Status-Check                             #
############################################
sleep 5
RUNNING_COUNT="$(exec_ct "cd /opt/cryptomator-hub && docker compose ps --status running -q | wc -l" 2>/dev/null || echo "0")"

if [[ "${RUNNING_COUNT:-0}" -eq 0 ]]; then
  msgbox "Warnung" \
"Docker Compose wurde gestartet, aber es konnten keine laufenden Container bestätigt werden.\n\n\
Keycloak braucht beim ersten Start bis zu 2 Minuten.\n\n\
Prüfe manuell:\n\
  pct enter ${CTID}\n\
  cd /opt/cryptomator-hub\n\
  docker compose ps\n\
  docker compose logs --tail=80"
fi

LXC_IP="$(get_lxc_ip "$CTID")"

############################################
# Abschluss                                #
############################################
if [[ "$KC_MODE" == "internal" ]]; then
  msgbox "Fertig – Installation abgeschlossen" \
"LXC: ${CTID}  |  Hostname: ${HOSTNAME}\n\
LXC IP: ${LXC_IP}\n\n\
Hub:\n\
  Intern:  http://${LXC_IP}:${HUB_BIND_PORT}\n\
  Public:  ${HUB_PUBLIC_BASE}\n\n\
Keycloak (ohne /kc):\n\
  Intern:  http://${LXC_IP}:${KC_BIND_PORT}\n\
  Public:  ${KC_PUBLIC_BASE}\n\
  Realm:   ${REALM_NAME}\n\
  Admin:   ${REALM_ADMIN_USER}\n\n\
LXC root Passwort (Notfall): ${LXC_ROOT_PW}\n\n\
Hinweis:\n\
  - Keycloak braucht beim 1. Start bis zu 2 Minuten."
else
  msgbox "Fertig – Installation abgeschlossen" \
"LXC: ${CTID}  |  Hostname: ${HOSTNAME}\n\
LXC IP: ${LXC_IP}\n\n\
Hub:\n\
  Intern:  http://${LXC_IP}:${HUB_BIND_PORT}\n\
  Public:  ${HUB_PUBLIC_BASE}\n\n\
Keycloak (extern, ohne /kc): ${KC_PUBLIC_BASE}\n\
  Realm: ${REALM_NAME}\n\n\
LXC root Passwort (Notfall): ${LXC_ROOT_PW}\n\n\
Wichtig:\n\
  - Externen Keycloak korrekt konfigurieren (Clients/Mapper/Secrets), sonst 401/403 und weisse UI."
fi

echo "Done. LXC IP: ${LXC_IP}"
