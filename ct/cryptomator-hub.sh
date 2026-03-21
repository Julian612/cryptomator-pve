#!/usr/bin/env bash

# Copyright (c) 2021-2025 community-scripts ORG
# Author: Julian612
# License: MIT
# Source: https://github.com/cryptomator/hub

source <(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)

APP="Cryptomator-Hub"
var_tags="${var_tags:-docker;cryptomator}"
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-2048}"
var_disk="${var_disk:-16}"
var_os="${var_os:-debian}"
var_version="${var_version:-12}"
var_unprivileged="${var_unprivileged:-1}"

header_info "$APP"
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  if [[ ! -d /opt/cryptomator-hub ]]; then
    msg_error "Keine ${APP} Installation gefunden!"
    exit 1
  fi

  msg_info "Aktualisiere ${APP}"
  $STD docker compose -f /opt/cryptomator-hub/compose.yml --env-file /opt/cryptomator-hub/.env pull
  $STD docker compose -f /opt/cryptomator-hub/compose.yml --env-file /opt/cryptomator-hub/.env up -d
  msg_ok "Aktualisierung abgeschlossen"
}

start
build_container
description

msg_ok "Abgeschlossen – ${APP} wurde erfolgreich installiert."
echo ""
echo -e "${APP} LXC installiert:"
echo -e "  Hub:      http://${IP}:8082"
echo -e "  Keycloak: http://${IP}:8081"
echo -e "  Logs:     pct enter <CTID> && cd /opt/cryptomator-hub && docker compose logs -f"
