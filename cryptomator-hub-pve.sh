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
# UI (whiptail) – PVE Helper Look & Cursor #
############################################
export DEBIAN_FRONTEND=noninteractive
export NCURSES_NO_UTF8_ACS=1

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
}

# Bei unerwartetem Fehler (set -e): Zeilennummer und Befehl anzeigen
on_error() {
  local exit_code=$? line="$1" cmd="$2"
  tput cnorm >/dev/null 2>&1 || true
  local _errmsg
  _errmsg=$'Script abgebrochen.\n\nZeile:     '
  _errmsg+="${line}"
  _errmsg+=$'\nExit code: '
  _errmsg+="${exit_code}"
  _errmsg+=$'\n\nBefehl:\n  '
  _errmsg+="${cmd}"
  _errmsg+=$'\n\nDetails: cat /tmp/cryptomator-hub-install.log'
  whiptail --title "Unerwarteter Fehler" --msgbox "$_errmsg" 16 78 2>/dev/null || true
  echo "ERROR Zeile ${line}: ${cmd} (exit ${exit_code})" >&2
}

trap cleanup EXIT
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
tput cnorm >/dev/null 2>&1 || true

############################################
# Helpers                                  #
############################################
die() {
  local msg="$*"
  # Fehler sowohl als msgbox (sichtbar) als auch auf stderr
  # printf -v interpretiert \n zu echten Newlines fuer whiptail
  local _dmsg
  printf -v _dmsg "%b" "$msg"
  whiptail --title "FEHLER" --msgbox "$_dmsg" 14 78 2>/dev/null || true
  echo "ERROR: $msg" >&2
  exit 1
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Befehl fehlt: $1"; }

# WICHTIG: whiptail interpretiert \n in Strings NICHT automatisch als Newline.
# Alle mehrzeiligen Texte werden deshalb als Variablen mit $'...' (ANSI-C Quoting)
# definiert. Nur so entstehen echte Newlines im String.

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

# Statusanzeige: whiptail --infobox (kein Input, kein FIFO, kein Hintergrundprozess).
# Zeigt eine nicht-blockierende Nachricht. Vollstaendig deadlock-frei.
# Output langer Befehle wird in Logdatei umgeleitet.
_INSTALL_LOG="/tmp/cryptomator-hub-install.log"

infobox() {
  whiptail --title "${1:-Info}" --infobox "${2:-}" 8 78
}

# spinner_start zeigt infobox VOR dem Befehl.
# spinner_stop raeut auf (hier nichts zu tun).
spinner_start() {
  infobox "${1:-}" "${2:-}"
}

spinner_stop() {
  true
}

is_int()   { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
rand_hex() { openssl rand -hex "${1:-16}"; }

############################################
# Preconditions                             #
############################################
need_cmd whiptail
need_cmd pveam
need_cmd pct
need_cmd pvesm
need_cmd pvesh
need_cmd awk
need_cmd openssl

if [[ "${EUID}" -ne 0 ]]; then
  die "Bitte als root auf dem Proxmox Host ausfuehren."
fi

############################################
# Storage-Auswahl per Menü                  #
############################################
# Template-Storage (vztmpl)
pick_tmpl_storage() {
  local menu_args=()
  while IFS= read -r stor; do
    [[ -n "$stor" ]] && menu_args+=("$stor" "Template Storage")
  done < <(pvesm status -content vztmpl | awk 'NR>1 {print $1}')

  [[ ${#menu_args[@]} -gt 0 ]] || \
    die "Kein Storage mit Content 'vztmpl' gefunden. Pruefe pvesm status."

  if [[ ${#menu_args[@]} -eq 2 ]]; then
    echo "${menu_args[0]}"
  else
    menulist "Storage (Template)" "Storage fuer LXC Template-Download:" 16 78 8 "${menu_args[@]}"
  fi
}

# Rootfs-Storage – zeigt alle verfuegbaren Storages mit Typ zur manuellen Auswahl.
# Kein Filter nach rootdir, da pvesm die Inhaltstypen unterschiedlich meldet.
pick_rootfs_storage() {
  local menu_args=()
  # Alle Storages einlesen mit Typ als Beschreibung (Spalten: Name Typ ...)
  while IFS= read -r line; do
    local sname stype
    sname="$(echo "$line" | awk '{print $1}')"
    stype="$(echo "$line" | awk '{print $2}')"
    [[ -n "$sname" ]] && menu_args+=("$sname" "[$stype]")
  done < <(pvesm status 2>/dev/null | awk 'NR>1')

  if [[ ${#menu_args[@]} -eq 0 ]]; then
    # Absoluter Fallback: manuelle Eingabe
    inputbox "Storage" "Kein Storage gefunden.\nBitte Storage-Name manuell eingeben (z.B. local-lvm):" "local-lvm"
    return
  fi

  if [[ ${#menu_args[@]} -eq 2 ]]; then
    # Nur ein Storage – direkt nehmen
    echo "${menu_args[0]}"
  else
    menulist "Storage (Container-Disk)"       "Storage fuer LXC Container-Disk waehlen.\nHinweis: local = nur Templates, local-lvm/local-zfs = Container."       20 78 12 "${menu_args[@]}"
  fi
}

############################################
# Template                                  #
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
  # grep gibt exit 1 wenn nicht gefunden – das ist hier erwartet, kein Fehler
  if ! pveam list "$storage" 2>/dev/null | awk '{print $1}' | grep -qFx "$tmpl"; then
    local msg
    msg=$'Debian Template nicht lokal vorhanden.\n\nLade herunter:\n'"${tmpl}"$'\n\nStorage: '"${storage}"$'\n\nDies kann einige Minuten dauern...'
    msgbox "Template Download" "$msg"
    spinner_start "Template Download" "Lade ${tmpl}..."
    pveam download "$storage" "$tmpl" >>"$_INSTALL_LOG" 2>&1
    local rc=$?
    spinner_stop
    [[ $rc -eq 0 ]] || die "Template Download fehlgeschlagen. Log: $_INSTALL_LOG"
  fi
}

############################################
# next-free CTID                            #
############################################
next_free_ctid() {
  pvesh get /cluster/nextid 2>/dev/null || echo "100"
}

############################################
# LXC-IP ermitteln                          #
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
# Gather Inputs                             #
############################################
BACKTITLE="Cryptomator Hub Installer (PVE Helper-artig)"

_MSG_WELCOME=$'Dieses Script erstellt einen Debian LXC Container und deployt:\n\n  - Cryptomator Hub\n  - Postgres\n  - Optional: Keycloak (intern)\n\nDu kannst zwischen Standard (Defaults) und Erweitert waehlen.\nIm Standard-Modus werden nur die wichtigsten Werte abgefragt.'
whiptail --backtitle "$BACKTITLE" --title "Cryptomator Hub" --msgbox "$_MSG_WELCOME" 16 78

############################################
# Standard vs. Erweitert                    #
############################################
INSTALL_MODE="$(radiolist "Installationsmodus" "Modus waehlen:" 12 78 2 \
  "standard"  "Standard  - sinnvolle Defaults, minimale Eingaben (empfohlen)" ON \
  "advanced"  "Erweitert - alle Parameter manuell konfigurieren" OFF \
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

if [[ "$INSTALL_MODE" == "standard" ]]; then
  # ---- STANDARD ----

  CTID="$(inputbox "Container" "CTID (naechste freie ID vorausgefuellt):" "$DEFAULT_CTID")" || exit 1
  is_int "$CTID" || die "CTID muss numerisch sein."

  HOSTNAME="$(inputbox "Container" "LXC Hostname:" "$DEFAULT_HOSTNAME")" || exit 1

  _MSG_KC=$'Keycloak Modus:\n\n- Intern: Script richtet Realm/Clients/Mapper automatisch ein.\n- Extern: Alles muss manuell korrekt konfiguriert werden.\n\nTypische Fehler bei Extern: 401/403, weisse UI.\nEmpfehlung: Intern waehlen.'
  msgbox "Keycloak Modus" "$_MSG_KC"

  KC_MODE="$(radiolist "Keycloak" "Keycloak Deployment:" 12 78 2 \
    "internal" "Keycloak im selben LXC deployen (empfohlen)" ON \
    "external" "Externen Keycloak verwenden (manuelle Konfig noetig)" OFF \
  )" || exit 1

  HUB_PUBLIC_BASE="$(inputbox "URLs" "Hub Public Base URL (z.B. https://hub.example.tld):" "https://hub.example.tld")" || exit 1
  KC_PUBLIC_BASE="$(inputbox  "URLs" "Keycloak Public Base URL ohne /kc (z.B. https://auth.example.tld):" "https://auth.example.tld")" || exit 1

  REALM_ADMIN_PW="$(passwordbox "Realm" "Initiales Realm-Admin Passwort:")" || exit 1
  [[ -n "$REALM_ADMIN_PW" ]] || die "Realm-Admin Passwort darf nicht leer sein."

  TZ="$DEFAULT_TZ"
  CORES="$DEFAULT_CORES"
  RAM="$DEFAULT_RAM"
  DISK="$DEFAULT_DISK"
  SWAP="$DEFAULT_SWAP"
  BRIDGE="$DEFAULT_BRIDGE"
  BIND_IP="$DEFAULT_BINDIP"
  KC_BIND_PORT="$DEFAULT_KC_PORT"
  HUB_BIND_PORT="$DEFAULT_HUB_PORT"
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
  # ---- ERWEITERT ----

  CTID="$(inputbox "Container" "CTID (numerisch):" "$DEFAULT_CTID")" || exit 1
  is_int "$CTID" || die "CTID muss numerisch sein."

  HOSTNAME="$(inputbox "Container" "LXC Hostname:" "$DEFAULT_HOSTNAME")" || exit 1
  TZ="$(inputbox "Container" "Zeitzone im LXC:" "$DEFAULT_TZ")" || exit 1

  _MSG_KC=$'Keycloak Modus:\n\n- Intern: Script richtet Realm/Clients/Mapper automatisch ein.\n- Extern: Du musst Realm/Clients/Mapper/Secrets selbst korrekt konfigurieren.\n\nTypische Fehler: 401/403, weisse UI, fehlende Rollen im Token.\nEmpfehlung: Intern waehlen.'
  msgbox "Keycloak Modus" "$_MSG_KC"

  KC_MODE="$(radiolist "Keycloak" "Keycloak Deployment auswählen:" 14 78 2 \
    "internal" "Keycloak im selben LXC deployen (empfohlen)" ON \
    "external" "Externen Keycloak verwenden (manuelle Konfiguration noetig)" OFF \
  )" || exit 1

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
    "static" "Statisch - IP/GW/DNS manuell eingeben" OFF \
  )" || exit 1

  if [[ "$NET_MODE" == "static" ]]; then
    STATIC_IP="$(inputbox "Netzwerk" "Statische IP mit Prefix (z.B. 192.168.1.50/24):" "")" || exit 1
    [[ -n "$STATIC_IP" ]] || die "Statische IP darf nicht leer sein."
    STATIC_GW="$(inputbox "Netzwerk" "Gateway (z.B. 192.168.1.1):" "")" || exit 1
    [[ -n "$STATIC_GW" ]] || die "Gateway darf nicht leer sein."
    STATIC_DNS="$(inputbox "Netzwerk" "DNS Server (z.B. 1.1.1.1):" "1.1.1.1")" || exit 1
  fi

  BIND_IP="$(inputbox "Ports" "Bind IP (0.0.0.0 = LAN, 127.0.0.1 = nur lokal):" "$DEFAULT_BINDIP")" || exit 1

  KC_BIND_PORT="$(inputbox "Ports" "Keycloak Host-Port (-> Container 8080):" "$DEFAULT_KC_PORT")" || exit 1
  is_int "$KC_BIND_PORT" || die "Keycloak Port muss numerisch sein."

  HUB_BIND_PORT="$(inputbox "Ports" "Hub Host-Port (-> Container 8080):" "$DEFAULT_HUB_PORT")" || exit 1
  is_int "$HUB_BIND_PORT" || die "Hub Port muss numerisch sein."

  [[ "$KC_BIND_PORT" != "$HUB_BIND_PORT" ]] || die "Keycloak Port und Hub Port duerfen nicht identisch sein."

  HUB_PUBLIC_BASE="$(inputbox "URLs" "Hub Public Base URL (z.B. https://hub.example.tld):" "https://hub.example.tld")" || exit 1
  KC_PUBLIC_BASE="$(inputbox  "URLs" "Keycloak Public Base URL ohne /kc (z.B. https://auth.example.tld):" "https://auth.example.tld")" || exit 1

  POSTGRES_IMAGE="$(inputbox "Images" "Postgres Image:" "$DEFAULT_PG_IMAGE")" || exit 1
  [[ -n "$POSTGRES_IMAGE" ]] || POSTGRES_IMAGE="$DEFAULT_PG_IMAGE"
  HUB_IMAGE="$(inputbox "Images" "Hub Image:" "$DEFAULT_HUB_IMAGE")" || exit 1
  [[ -n "$HUB_IMAGE" ]] || HUB_IMAGE="$DEFAULT_HUB_IMAGE"
  KEYCLOAK_IMAGE="$(inputbox "Images" "Keycloak Image:" "$DEFAULT_KC_IMAGE")" || exit 1
  [[ -n "$KEYCLOAK_IMAGE" ]] || KEYCLOAK_IMAGE="$DEFAULT_KC_IMAGE"

  HUB_OIDC_CLIENT_ID="$(inputbox "OIDC" "OIDC Client ID (Hub) in Keycloak:" "$DEFAULT_OIDC_CLIENT")" || exit 1
  HUB_SYSTEM_CLIENT_ID="$(inputbox "OIDC" "System Client ID fuer Hub-Sync:" "$DEFAULT_SYSTEM_CLIENT")" || exit 1
  HUB_REDIRECT_URI="$(inputbox "OIDC" "Hub Redirect URI:" "${HUB_PUBLIC_BASE}/*")" || exit 1

  REALM_NAME="$(inputbox "Realm" "Realm Name:" "$DEFAULT_REALM")" || exit 1
  REALM_ADMIN_USER="$(inputbox "Realm" "Initialer Realm-Admin Username:" "$DEFAULT_REALM_ADMIN")" || exit 1
  REALM_ADMIN_PW="$(passwordbox "Realm" "Initiales Realm-Admin Passwort:")" || exit 1
  [[ -n "$REALM_ADMIN_PW" ]] || die "Realm-Admin Passwort darf nicht leer sein."

  REALM_ADMIN_TEMP="true"
  if yesno "Realm" "Realm-Admin Passwort bei erstem Login aendern erzwingen?"; then
    REALM_ADMIN_TEMP="true"
  else
    REALM_ADMIN_TEMP="false"
  fi
fi

############################################
# Externer Keycloak: Client Secret          #
############################################
HUB_SYSTEM_CLIENT_SECRET=""
if [[ "$KC_MODE" == "external" ]]; then
  _MSG_EXT=$'Du musst im externen Keycloak manuell anlegen:\n\n  - Realm:   '"${REALM_NAME}"$'\n  - Clients: cryptomatorhub, cryptomator, '"${HUB_SYSTEM_CLIENT_ID}"$'\n  - Protocol Mappers (Rollen im Token)\n  - Client Secret fuer '"${HUB_SYSTEM_CLIENT_ID}"$'\n\nOhne korrekte Konfiguration: 401/403 und weisse Hub-UI.'
  msgbox "Warnung (Externer Keycloak)" "$_MSG_EXT"
  HUB_SYSTEM_CLIENT_SECRET="$(passwordbox "External Keycloak" "Client Secret fuer ${HUB_SYSTEM_CLIENT_ID}:")" || exit 1
  [[ -n "$HUB_SYSTEM_CLIENT_SECRET" ]] || die "Client Secret darf nicht leer sein (external keycloak)."
fi

############################################
# Zusammenfassung vor Installation          #
############################################
_MSG_CONFIRM=$'Folgende Konfiguration wird installiert:\n\n  CTID:      '"${CTID}"$'\n  Hostname:  '"${HOSTNAME}"$'\n  Keycloak:  '"${KC_MODE}"$'\n  Hub URL:   '"${HUB_PUBLIC_BASE}"$'\n  KC URL:    '"${KC_PUBLIC_BASE}"$'\n  Realm:     '"${REALM_NAME:-cryptomator}"$'\n\nFortfahren?'
yesno "Bestaetigung" "$_MSG_CONFIRM" || { echo "Abgebrochen."; exit 0; }

############################################
# Storage / Template                        #
############################################
TMPL_STORAGE="$(pick_tmpl_storage)"
ROOTFS_STORAGE="$(pick_rootfs_storage)"
TEMPLATE="$(latest_debian12_template)"
if [[ -z "$TEMPLATE" ]]; then
  # pveam available nochmal mit Output fuer Diagnose
  _avail="$(pveam available --section system 2>&1 | head -20 || true)"
  die "Kein debian-12-standard Template gefunden.\n\npveam available Output:\n${_avail}"
fi
ensure_template "$TMPL_STORAGE" "$TEMPLATE"

############################################
# LXC erstellen                             #
############################################
if pct status "$CTID" >/dev/null 2>&1; then
  die "CTID $CTID existiert bereits. Bitte einen freien CTID waehlen oder den Container zuerst loeschen."
fi

LXC_ROOT_PW="$(rand_hex 8)"

if [[ "$NET_MODE" == "static" ]]; then
  NET0="name=eth0,bridge=${BRIDGE},ip=${STATIC_IP},gw=${STATIC_GW},type=veth"
  PCT_CREATE_ARGS=(
    --hostname    "$HOSTNAME"
    --cores       "$CORES"
    --memory      "$RAM"
    --swap        "$SWAP"
    --rootfs      "${ROOTFS_STORAGE}:${DISK}"
    --net0        "$NET0"
    --nameserver  "$STATIC_DNS"
    --features    "nesting=1,keyctl=1"
    --unprivileged 1
    --timezone    "$TZ"
    --password    "$LXC_ROOT_PW"
    --onboot      1
  )
else
  NET0="name=eth0,bridge=${BRIDGE},ip=dhcp,type=veth"
  # DNS vom PVE-Host uebernehmen damit der Container nach dem Start sofort
  # Namen aufloesen kann (DHCP liefert DNS manchmal zu spaet oder gar nicht)
  _HOST_DNS="$(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || echo "1.1.1.1")"
  PCT_CREATE_ARGS=(
    --hostname    "$HOSTNAME"
    --cores       "$CORES"
    --memory      "$RAM"
    --swap        "$SWAP"
    --rootfs      "${ROOTFS_STORAGE}:${DISK}"
    --net0        "$NET0"
    --nameserver  "$_HOST_DNS"
    --features    "nesting=1,keyctl=1"
    --unprivileged 1
    --timezone    "$TZ"
    --password    "$LXC_ROOT_PW"
    --onboot      1
  )
fi

spinner_start "LXC" "Erstelle Container ${CTID} (${HOSTNAME})..."
pct create "$CTID" "${TMPL_STORAGE}:vztmpl/${TEMPLATE}" "${PCT_CREATE_ARGS[@]}" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "pct create fehlgeschlagen. Log: $_INSTALL_LOG"

pct start "$CTID" || die "pct start fehlgeschlagen."

spinner_start "LXC" "Warte auf Container-Start..."
_ct_ready=0
for _i in $(seq 1 30); do
  if pct exec "$CTID" -- true </dev/null 2>/dev/null; then
    _ct_ready=1
    break
  fi
  sleep 2
done
spinner_stop
[[ $_ct_ready -eq 1 ]] || die "Container antwortet nach 60s nicht. Pruefe: pct status $CTID"

############################################
# exec_ct – ab hier verfügbar              #
############################################
exec_ct() {
  # </dev/null verhindert, dass pct exec auf stdin haengt
  # (bekanntes Problem bei manchen PVE-Versionen)
  pct exec "$CTID" -- bash -lc "$1" </dev/null
}

# write_ct_file – schreibt Datei via base64 in den Container.
# Vermeidet stdin-Piping durch pct exec (haengt bei manchen PVE-Versionen).
# Usage: write_ct_file /ziel/pfad [mode] <<'MARKER'
#        Inhalt
#        MARKER
write_ct_file() {
  local dest="$1" mode="${2:-0644}"
  local b64
  b64="$(base64 -w0)"
  exec_ct "printf '%s' '${b64}' | base64 -d > '${dest}' && chmod ${mode} '${dest}'"
}

############################################
# Bootstrap im Container                    #
############################################
# Feste Wartezeit damit DHCP und Netz sich stabilisieren koennen.
# Kein DNS-Vorcheck – apt-get gibt eine klare Fehlermeldung wenn Netz fehlt.
spinner_start "Netzwerk" "Warte 20s auf Netzwerk-Initialisierung im Container..."
sleep 20
spinner_stop

spinner_start "Bootstrap" "apt-get update..."
exec_ct "DEBIAN_FRONTEND=noninteractive apt-get update -y" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "apt-get update fehlgeschlagen. Log: $_INSTALL_LOG"

spinner_start "Bootstrap" "Installiere Docker (ca. 1-2 Minuten)..."
exec_ct "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg docker.io docker-compose-plugin" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "Docker Installation fehlgeschlagen. Log: $_INSTALL_LOG"

spinner_start "Bootstrap" "Starte Docker Service..."
exec_ct "systemctl enable --now docker" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop; [[ $_rc -eq 0 ]] || die "Docker Service konnte nicht gestartet werden. Log: $_INSTALL_LOG"

############################################
# Deployment-Verzeichnisse anlegen          #
############################################
exec_ct "mkdir -p \
  /opt/cryptomator-hub/data/db-init \
  /opt/cryptomator-hub/data/db-data \
  /opt/cryptomator-hub/kc-import" \
  || die "Verzeichnisse konnten nicht angelegt werden."

############################################
# Secrets generieren                        #
############################################
POSTGRES_PASSWORD="$(rand_hex 24)"
HUB_DB_PASSWORD="$(rand_hex 24)"
KC_DB_PASSWORD="$(rand_hex 24)"
if [[ "$KC_MODE" == "internal" ]]; then
  HUB_SYSTEM_CLIENT_SECRET="$(rand_hex 24)"
fi

CSP="default-src 'self'; connect-src 'self' api.cryptomator.org ${KC_PUBLIC_BASE}; object-src 'none'; child-src 'self'; img-src * data:; frame-ancestors 'none'"

############################################
# initdb.sql schreiben                      #
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
# .env schreiben                            #
# Kein quoted Heredoc: Host-Vars werden    #
# expandiert und in den Container gepipet. #
############################################
KC_DB_PW_VALUE=""
USE_EXTERNAL_VALUE="no"
if [[ "$KC_MODE" == "internal" ]]; then
  KC_DB_PW_VALUE="${KC_DB_PASSWORD}"
else
  USE_EXTERNAL_VALUE="yes"
fi

spinner_start "Konfiguration" "Schreibe .env..."
write_ct_file /opt/cryptomator-hub/.env 0600 <<ENV
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

QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE=${CSP}
ENV
[[ $? -eq 0 ]] || die ".env konnte nicht geschrieben werden."
spinner_stop

############################################
# realm.json (nur interner Keycloak)        #
############################################
if [[ "$KC_MODE" == "internal" ]]; then
  spinner_start "Konfiguration" "Schreibe realm.json..."
  write_ct_file /opt/cryptomator-hub/kc-import/realm.json <<REALM
{
  "id": "cryptomator",
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
    },
    {
      "username": "system",
      "email": "system@localhost",
      "enabled": true,
      "serviceAccountClientId": "${HUB_SYSTEM_CLIENT_ID}",
      "clientRoles": {"realm-management": ["realm-admin","view-system"]}
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
            "claim.name": "resource_access.\${client_id}.roles",
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
      "standardFlowEnabled": false
    }
  ]
}
REALM
  [[ $? -eq 0 ]] || die "realm.json konnte nicht geschrieben werden."
  spinner_stop
fi

############################################
# compose.yml schreiben                     #
# Single-quoted Heredoc: $ bleibt erhalten #
# damit docker-compose die Vars liest.     #
############################################
spinner_start "Konfiguration" "Schreibe compose.yml..."
if [[ "$KC_MODE" == "internal" ]]; then
  write_ct_file /opt/cryptomator-hub/compose.yml <<'COMPOSE'
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

  write_ct_file /opt/cryptomator-hub/compose.yml <<'COMPOSE'
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
spinner_stop

############################################
# Deploy                                     #
############################################
spinner_start "Deploy" "Lade Docker Images (kann einige Minuten dauern)..."
exec_ct "cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml pull" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop
[[ $_rc -eq 0 ]] || die "docker compose pull fehlgeschlagen. Log: $_INSTALL_LOG"

spinner_start "Deploy" "Starte Container (Keycloak braucht beim ersten Start bis zu 2-3 Minuten)..."
exec_ct "cd /opt/cryptomator-hub && docker compose --env-file .env -f compose.yml up -d" >>"$_INSTALL_LOG" 2>&1
_rc=$?; spinner_stop
[[ $_rc -eq 0 ]] || die "docker compose up fehlgeschlagen. Pruefe: pct enter ${CTID} -> cd /opt/cryptomator-hub && docker compose logs"

############################################
# Status-Check nach Deploy                   #
############################################
sleep 10
RUNNING_COUNT="$(exec_ct \
  "docker compose -f /opt/cryptomator-hub/compose.yml ps --status running --quiet 2>/dev/null | wc -l" \
  2>/dev/null || echo "0")"

if [[ "$KC_MODE" == "internal" ]]; then
  _expected=3
else
  _expected=2
fi

if [[ "${RUNNING_COUNT:-0}" -lt "$_expected" ]]; then
  _MSG_WARN=$'Docker Compose wurde gestartet, aber nicht alle Container laufen.\n('"${RUNNING_COUNT:-0}"' von '"${_expected}"$' erwartet)\n\nKeycloak braucht beim ersten Start bis zu 2-3 Minuten.\n\nPruefe manuell:\n  pct enter '"${CTID}"$'\n  cd /opt/cryptomator-hub\n  docker compose ps\n  docker compose logs --tail=50'
  msgbox "Warnung" "$_MSG_WARN"
fi

############################################
# LXC-IP ermitteln                          #
############################################
LXC_IP="$(get_lxc_ip "$CTID")"

############################################
# Abschluss-Zusammenfassung                 #
############################################
if [[ "$KC_MODE" == "internal" ]]; then
  _MSG_DONE=$'LXC: '"${CTID}"'  |  Hostname: '"${HOSTNAME}"$'\nLXC IP: '"${LXC_IP}"$'\n\nHub:\n  Intern:  http://'"${LXC_IP}"':'"${HUB_BIND_PORT}"$'\n  Public:  '"${HUB_PUBLIC_BASE}"$'\n\nKeycloak:\n  Intern:  http://'"${LXC_IP}"':'"${KC_BIND_PORT}"$'\n  Public:  '"${KC_PUBLIC_BASE}"$'\n  Realm:   '"${REALM_NAME}"$'\n  Admin:   '"${REALM_ADMIN_USER}"$'  (Passwort wie eingegeben)\n\nLXC root Passwort (Notfall): '"${LXC_ROOT_PW}"$'\n\nHinweise:\n  - Keycloak braucht beim 1. Start bis zu 2 Minuten.\n  - Kein /kc Pfad - direkt ueber Root-Pfad erreichbar.\n  - Reverse Proxy: Hub/Keycloak ueber unterschiedliche Ports/Domains.'
  msgbox "Installation abgeschlossen" "$_MSG_DONE"
else
  _MSG_DONE=$'LXC: '"${CTID}"'  |  Hostname: '"${HOSTNAME}"$'\nLXC IP: '"${LXC_IP}"$'\n\nHub:\n  Intern:  http://'"${LXC_IP}"':'"${HUB_BIND_PORT}"$'\n  Public:  '"${HUB_PUBLIC_BASE}"$'\n\nKeycloak (extern): '"${KC_PUBLIC_BASE}"$'\n  Realm: '"${REALM_NAME}"$'\n\nLXC root Passwort (Notfall): '"${LXC_ROOT_PW}"$'\n\nWichtig:\n  - Realm/Clients/Mapper/Secrets im externen Keycloak\n    korrekt konfigurieren - sonst 401/403 und weisse UI.'
  msgbox "Installation abgeschlossen" "$_MSG_DONE"
fi

echo "Done. LXC IP: ${LXC_IP}"
