#!/usr/bin/env bash

# Copyright (c) 2021-2025 community-scripts ORG
# Author: Julian612
# License: MIT
# Source: https://github.com/cryptomator/hub

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

# Image versions (overridable via env)
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:14-alpine}"
HUB_IMAGE="${HUB_IMAGE:-ghcr.io/cryptomator/hub:stable}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-ghcr.io/cryptomator/keycloak:26.5.3}"

KC_BIND_PORT="${KC_BIND_PORT:-8081}"
HUB_BIND_PORT="${HUB_BIND_PORT:-8082}"
BIND_IP="${BIND_IP:-0.0.0.0}"

REALM_NAME="${REALM_NAME:-cryptomator}"
REALM_ADMIN_USER="${REALM_ADMIN_USER:-admin}"
HUB_OIDC_CLIENT_ID="${HUB_OIDC_CLIENT_ID:-cryptomatorhub}"
HUB_SYSTEM_CLIENT_ID="${HUB_SYSTEM_CLIENT_ID:-cryptomatorhub-system}"

# Derive public URLs from container IP (user can update .env afterward)
CONTAINER_IP="$(hostname -I | awk '{print $1}')"
HUB_PUBLIC_BASE="${HUB_PUBLIC_BASE:-http://${CONTAINER_IP}:${HUB_BIND_PORT}}"
KC_PUBLIC_BASE="${KC_PUBLIC_BASE:-http://${CONTAINER_IP}:${KC_BIND_PORT}}"

msg_info "Installiere Abhängigkeiten"
$STD apt-get install -y ca-certificates curl gnupg
msg_ok "Abhängigkeiten installiert"

msg_info "Installiere Docker"
$STD apt-get install -y docker.io docker-compose-plugin
$STD systemctl enable --now docker
msg_ok "Docker installiert"

msg_info "Erstelle Verzeichnisse"
mkdir -p \
  /opt/cryptomator-hub/data/db-init \
  /opt/cryptomator-hub/data/db-data \
  /opt/cryptomator-hub/kc-import
msg_ok "Verzeichnisse erstellt"

# Generate secrets
POSTGRES_PASSWORD="$(openssl rand -hex 24)"
HUB_DB_PASSWORD="$(openssl rand -hex 24)"
KC_DB_PASSWORD="$(openssl rand -hex 24)"
HUB_SYSTEM_CLIENT_SECRET="$(openssl rand -hex 24)"
REALM_ADMIN_PASSWORD="$(openssl rand -hex 16)"

CSP="default-src 'self'; connect-src 'self' api.cryptomator.org ${KC_PUBLIC_BASE}; object-src 'none'; child-src 'self'; img-src * data:; frame-ancestors 'none'"

HUB_REDIRECT_URI="${HUB_PUBLIC_BASE}/*"

msg_info "Schreibe initdb.sql"
cat >/opt/cryptomator-hub/data/db-init/initdb.sql <<SQL
CREATE USER keycloak WITH ENCRYPTED PASSWORD '${KC_DB_PASSWORD}';
CREATE DATABASE keycloak WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

CREATE USER hub WITH ENCRYPTED PASSWORD '${HUB_DB_PASSWORD}';
CREATE DATABASE hub WITH ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE hub TO hub;
SQL
msg_ok "initdb.sql geschrieben"

msg_info "Schreibe .env"
cat >/opt/cryptomator-hub/.env <<ENV
# Cryptomator Hub deployment (.env)
# WICHTIG: Diese Datei enthaelt Secrets. Nicht in Git einchecken.
# Passe HUB_PUBLIC_BASE und KC_PUBLIC_BASE an deine Domain an!

USE_EXTERNAL_KC=no

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
KC_DB_PASSWORD=${KC_DB_PASSWORD}

HUB_OIDC_CLIENT_ID=${HUB_OIDC_CLIENT_ID}
HUB_SYSTEM_CLIENT_ID=${HUB_SYSTEM_CLIENT_ID}
HUB_SYSTEM_CLIENT_SECRET=${HUB_SYSTEM_CLIENT_SECRET}

EXTERNAL_KC_REALM=${REALM_NAME}
KC_INTERNAL_URL=http://keycloak:8080
EXTERNAL_KC_ISSUER=${KC_PUBLIC_BASE}/realms/${REALM_NAME}
EXTERNAL_KC_AUTH_SERVER_URL=${KC_PUBLIC_BASE}/realms/${REALM_NAME}

HUB_REDIRECT_URI=${HUB_REDIRECT_URI}

REALM_ADMIN_USER=${REALM_ADMIN_USER}
REALM_ADMIN_PASSWORD=${REALM_ADMIN_PASSWORD}
REALM_ADMIN_TEMPORARY=false

QUARKUS_HTTP_HEADER__CONTENT_SECURITY_POLICY__VALUE=${CSP}
ENV
chmod 600 /opt/cryptomator-hub/.env
msg_ok ".env geschrieben"

msg_info "Schreibe realm.json"
cat >/opt/cryptomator-hub/kc-import/realm.json <<REALM
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
        {"type":"password","value":"${REALM_ADMIN_PASSWORD}","temporary":false}
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
msg_ok "realm.json geschrieben"

msg_info "Schreibe compose.yml"
cat >/opt/cryptomator-hub/compose.yml <<'COMPOSE'
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
msg_ok "compose.yml geschrieben"

msg_info "Lade Docker Images"
$STD docker compose -f /opt/cryptomator-hub/compose.yml --env-file /opt/cryptomator-hub/.env pull
msg_ok "Docker Images geladen"

msg_info "Starte Cryptomator Hub Stack"
$STD docker compose -f /opt/cryptomator-hub/compose.yml --env-file /opt/cryptomator-hub/.env up -d
msg_ok "Cryptomator Hub Stack gestartet"

# Store credentials for display by ct/ script
mkdir -p /opt/cryptomator-hub
cat >/opt/cryptomator-hub/.install-summary <<SUMMARY
REALM_ADMIN_USER=${REALM_ADMIN_USER}
REALM_ADMIN_PASSWORD=${REALM_ADMIN_PASSWORD}
HUB_BIND_PORT=${HUB_BIND_PORT}
KC_BIND_PORT=${KC_BIND_PORT}
SUMMARY
chmod 600 /opt/cryptomator-hub/.install-summary

motd_ssh
customize

echo ""
echo "Cryptomator Hub wurde installiert."
echo ""
echo "  Hub URL:          http://$(hostname -I | awk '{print $1}'):${HUB_BIND_PORT}"
echo "  Keycloak URL:     http://$(hostname -I | awk '{print $1}'):${KC_BIND_PORT}"
echo "  Realm Admin:      ${REALM_ADMIN_USER}"
echo "  Admin Passwort:   ${REALM_ADMIN_PASSWORD}"
echo ""
echo "  Config: /opt/cryptomator-hub/.env"
echo ""
echo "  Hinweis: Passe HUB_PUBLIC_BASE und KC_PUBLIC_BASE in .env an,"
echo "  wenn du einen Reverse Proxy / eigene Domain verwendest."
echo "  Danach: cd /opt/cryptomator-hub && docker compose up -d"
