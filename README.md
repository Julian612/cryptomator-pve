# Cryptomator Hub – Proxmox VE Helper Script

Automatisiertes Deployment von **Cryptomator Hub** in einem Debian 12 LXC-Container auf **Proxmox VE**.

Interaktiver Installer mit whiptail-UI (PVE Helper-Stil) – erstellt den Container, installiert Docker, generiert alle Konfigurationsdateien und startet den Stack vollautomatisch.

---

## Features

- **Zwei Keycloak-Modi**
  - **Intern** – Keycloak wird im selben LXC mitinstalliert, Realm/Clients/Mapper werden automatisch importiert
  - **Extern** – Anbindung an eine bestehende Keycloak-Instanz (manuelle Konfiguration erforderlich)
- **Zwei Installationsmodi**
  - **Standard** – sinnvolle Defaults, nur die wichtigsten Werte werden abgefragt (CTID, Hostname, URLs, Passwort)
  - **Erweitert** – alle Parameter manuell konfigurierbar (CPU, RAM, Disk, Netzwerk, Ports, Images, OIDC, Realm)
- **Netzwerk** – DHCP oder statische IP-Konfiguration
- **Automatische Secret-Generierung** – alle Datenbank- und Client-Passwörter werden per `openssl rand` erzeugt
- **Docker-in-LXC** – unprivilegierter Container mit `nesting=1` und `keyctl=1`
- **Fehlerbehandlung** – `set -Eeuo pipefail`, Fehlerdialog mit Zeilennummer und Befehl, Logfile unter `/tmp/cryptomator-hub-install.log`

---

## Architektur

### Variante A – Interner Keycloak

```
Proxmox VE Host
└── LXC (Debian 12, unprivilegiert)
    └── Docker
        ├── PostgreSQL (Datenbank fuer Hub + Keycloak)
        ├── Keycloak   (Identity Provider, Realm wird automatisch importiert)
        └── Cryptomator Hub
```

- Vollstaendig eigenstaendig, kein externer Dienst noetig
- Realm `cryptomator` mit vorkonfigurierten Clients und Rollen
- Ideal fuer isolierte / neue Installationen

### Variante B – Externer Keycloak

```
Proxmox VE Host
└── LXC (Debian 12, unprivilegiert)
    └── Docker
        ├── PostgreSQL (Datenbank fuer Hub)
        └── Cryptomator Hub

Separater Keycloak (bestehend)
```

- Integration in bestehende IAM-Infrastruktur
- Realm/Clients/Mapper/Secrets muessen extern korrekt konfiguriert werden
- Ohne korrekte Konfiguration: 401/403-Fehler und weisse Hub-UI

---

## Voraussetzungen

- **Proxmox VE** (7.x oder 8.x)
- **Root-Zugriff** auf dem PVE-Host
- **Internetzugang** (Template-Download, Debian-Pakete, Docker-Images)
- **Storage** mit Content-Typ `vztmpl` (Templates) und ein Storage fuer Container-Disks (z.B. `local-lvm`, `local-zfs`)
- **Netzwerk-Bridge** (z.B. `vmbr0`)
- **Reverse Proxy** empfohlen (z.B. Nginx Proxy Manager, Traefik, Caddy) fuer HTTPS-Terminierung

---

## Installation

Auf dem **Proxmox VE Host** als root ausfuehren:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Julian612/cryptomator-pve/main/cryptomator-hub-pve.sh)"
```

Alternativ herunterladen und manuell starten:

```bash
curl -fsSL https://raw.githubusercontent.com/Julian612/cryptomator-pve/main/cryptomator-hub-pve.sh -o cryptomator-hub-pve.sh
chmod +x cryptomator-hub-pve.sh
./cryptomator-hub-pve.sh
```

Der interaktive Installer fuehrt durch alle Schritte:

1. Installationsmodus waehlen (Standard / Erweitert)
2. Keycloak-Modus waehlen (Intern / Extern)
3. Container-Parameter eingeben (CTID, Hostname, ggf. Ressourcen und Netzwerk)
4. URLs festlegen (Hub Public Base URL, Keycloak Public Base URL)
5. Realm-Admin-Passwort vergeben
6. Konfiguration bestaetigen und Installation starten

---

## Defaults (Standard-Modus)

| Parameter | Default |
|---|---|
| CPU Cores | 2 |
| RAM | 2048 MB |
| Disk | 16 GB |
| Swap | 512 MB |
| Bridge | `vmbr0` |
| Netzwerk | DHCP |
| Keycloak Port | 8081 |
| Hub Port | 8082 |
| Bind IP | `0.0.0.0` (LAN-erreichbar) |
| PostgreSQL Image | `postgres:14-alpine` |
| Hub Image | `ghcr.io/cryptomator/hub:stable` |
| Keycloak Image | `ghcr.io/cryptomator/keycloak:26.5.3` |
| Realm | `cryptomator` |
| Realm Admin | `admin` |

Im erweiterten Modus sind alle Parameter frei konfigurierbar.

---

## Ablauf des Scripts

```
 Willkommen / Modus-Auswahl
        │
        ▼
 Storage und Template auswaehlen
        │
        ▼
 LXC Container erstellen und starten
        │
        ▼
 Netzwerk-Initialisierung abwarten (20s)
        │
        ▼
 apt-get update + Docker installieren
        │
        ▼
 Konfigurationsdateien schreiben
   ├── initdb.sql  (PostgreSQL Datenbanken/User)
   ├── .env        (Secrets, Ports, URLs, Images)
   ├── realm.json  (Keycloak Realm, nur bei internem KC)
   └── compose.yml (Docker Compose Manifest)
        │
        ▼
 Docker Images laden (pull)
        │
        ▼
 Container starten (up -d)
        │
        ▼
 Status-Check und Zusammenfassung
```

---

## Nach der Installation

### Zugriff

- **Hub:** `http://<LXC-IP>:8082`
- **Keycloak (intern):** `http://<LXC-IP>:8081`
- **Realm-Admin:** Login mit dem bei der Installation vergebenen Passwort

### Erster Start

Keycloak braucht beim ersten Start **bis zu 2-3 Minuten** fuer die Initialisierung. Hub startet erst, wenn Keycloak gesund meldet.

### Manuell pruefen

```bash
pct enter <CTID>
cd /opt/cryptomator-hub
docker compose ps
docker compose logs --tail=50
```

### Reverse Proxy

Hub und Keycloak sollten ueber einen Reverse Proxy mit HTTPS erreichbar gemacht werden. Beide Dienste muessen unter den bei der Installation angegebenen Public Base URLs erreichbar sein.

---

## Dateien im Container

| Pfad | Beschreibung |
|---|---|
| `/opt/cryptomator-hub/.env` | Secrets, Ports, URLs, Image-Versionen |
| `/opt/cryptomator-hub/compose.yml` | Docker Compose Manifest |
| `/opt/cryptomator-hub/data/db-init/initdb.sql` | PostgreSQL Init-Script |
| `/opt/cryptomator-hub/data/db-data/` | PostgreSQL Daten (persistent) |
| `/opt/cryptomator-hub/kc-import/realm.json` | Keycloak Realm-Import (nur intern) |

---

## Troubleshooting

| Problem | Ursache | Loesung |
|---|---|---|
| Weisse Hub-UI / 401 / 403 | Keycloak-Konfiguration fehlerhaft | Realm, Clients, Mapper und Secrets pruefen |
| Hub startet nicht | Keycloak noch nicht bereit | 2-3 Minuten warten, `docker compose logs hub` pruefen |
| Container nicht erreichbar | DHCP fehlgeschlagen oder Firewall | `pct enter <CTID>`, `ip a`, DNS/Gateway pruefen |
| Docker pull schlaegt fehl | Kein Internet im Container | DNS pruefen: `pct exec <CTID> -- ping -c1 1.1.1.1` |

---

## Lizenz

[MIT](LICENSE)
