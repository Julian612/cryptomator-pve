# Cryptomator Hub – Proxmox VE Helper Script

Automatisiertes Deployment von **Cryptomator Hub** in einem Debian 12 LXC auf **Proxmox VE**.

Das Script unterstützt zwei Betriebsmodi:

- 🔐 Internal Keycloak (Keycloak wird mitinstalliert)
- 🌐 External Keycloak (bestehende Keycloak-Instanz wird verwendet)

---

# Ziel

Reproduzierbares, isoliertes Deployment von Cryptomator Hub in einer LXC-Umgebung ohne manuelle Docker- oder Keycloak-Konfiguration.

---

# Architektur

## Variante A – Internal Keycloak

Proxmox VE  
└── LXC (Debian 12)  
  ├── PostgreSQL  
  ├── Keycloak  
  └── Cryptomator Hub  

- Realm und Clients werden automatisch importiert
- Vollständig eigenständig
- Ideal für isolierte Installationen

---

## Variante B – External Keycloak

Proxmox VE  
└── LXC (Debian 12)  
  ├── PostgreSQL  
  └── Cryptomator Hub  

Separater Keycloak (bestehend)

- Integration in bestehende IAM-Struktur
- Zentralisiertes Identity Management
- Realm/Clients müssen extern vorbereitet werden

---

# Voraussetzungen

- Proxmox VE
- Root Zugriff auf PVE Host
- Internetzugang
- Storage (z.B. local-lvm oder ZFS)
- Netzwerk-Bridge (z.B. vmbr0)
- Reverse Proxy empfohlen

---

# Installation

Auf dem Proxmox Host ausführen:

```bash
chmod +x cryptomator-hub-pve.sh
./cryptomator-hub-pve.sh