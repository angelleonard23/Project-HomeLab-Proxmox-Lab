# 🧪 Enterprise HomeLab – Proxmox Security Infrastructure

> Enterprise-nahes HomeLab zur Vertiefung von Systemadministration, Netzwerk- & IT-Security  
> Fokus auf Netzwerksegmentierung, Firewalling, Server-Hardening, Active Directory, Containerisierung & Automatisierung

---

## 🎯 Projektziel

Aufbau eines realistischen Enterprise-HomeLabs zur praktischen Umsetzung von:

- Virtualisierung mit Proxmox
- Netzwerksegmentierung (VLANs, DMZ)
- Firewall- & Perimeter-Security
- Server- & Service-Hardening
- Windows Active Directory
- Docker & Automatisierung
- Monitoring & Logging

---

## 🏗️ Architektur – Überblick

Das HomeLab bildet eine klassische Unternehmensarchitektur ab:

- Trennung von Management, Server, Client und DMZ
- Zentrale Firewall mit pfSense
- VLAN-basierte Segmentierung
- Defense-in-Depth-Ansatz


---

## 🧱 Hardware & Plattform

### Virtualisierungshost
- AOOSTAR WTR PRO
- AMD Ryzen 7 5825U
- 64 GB RAM
- Proxmox VE (Bare Metal)

### Clients
- ASUS ROG Zephyrus G14 (Linux / Windows)
- MacBook Air (macOS)

---

## 🔀 Virtualisierung & Netzwerk (Proxmox)

- Proxmox VE mit Linux Bridges
- VLAN-aware Networking
- Isolierte Netzwerke pro Sicherheitszone
- Snapshot- & Backup-Strategie

---

## 🔥 Firewall & Perimeter Security (pfSense)

- Stateful Firewall (Default-Deny)
- Zonenbasierte Firewall-Regeln
- NAT & Port Forwarding
- DNS Resolver
- pfBlockerNG (DNS & IP Blocking)
- Zentrales Logging

---

## 🌐 Netzwerksegmentierung (VLANs)

| VLAN | Zweck        | Subnetz        |
|------|-------------|----------------|
| 10   | Management  | 10.0.10.0/24  |
| 20   | Server      | 10.0.20.0/24  |
| 30   | Client / DMZ| 10.0.30.0/24  |

Security-Prinzip:
- Management darf alle Netze erreichen
- Server & Clients dürfen nicht ins Management-Netz


---

## 🖥️ Server & Services

### Linux Server
- Ubuntu / Debian Server
- SSH-Hardening
- UFW Firewall
- Fail2Ban
- systemd Services
- Log-Analyse (/var/log/auth.log)


---

## 🔐 Webserver-Hardening

- Apache ServerTokens & ServerSignature deaktiviert
- Directory Listing deaktiviert
- Root-Login via SSH verboten
- Begrenzte Auth-Versuche
- Minimal installierte Services

---

## 📦 Containerisierung (Docker)

- Docker & Docker Compose
- Trennung von Web- & Datenbank-Containern
- Isolierte Container-Netzwerke
- Persistente Volumes
- Keine Datenbank-Ports nach außen


---

## 🪟 Windows Active Directory

- Active Directory Domain Controller
- DNS & DHCP
- OU-Struktur
- Benutzer- & Gruppenverwaltung
- Gruppenrichtlinien (GPOs)
- Login-Banner & Drive-Mapping


---

## 🗄️ File Server & Berechtigungen

- NTFS- & Share-Permissions
- AGDLP-Prinzip
- GPO-basiertes Drive-Mapping
- Shadow Copies (VSS)
- File Server Resource Manager
  - Quotas
  - File Screening

---

## ⚙️ Automatisierung & Backups

- Bash-Backup-Skripte
- Cronjobs
- SQL-Dumps
- Datei-Backups
- Regelmäßige Restore-Tests


---

## 📊 Monitoring & Logging

- pfSense Firewall Logs
- Linux Auth Logs
- Windows Event Logs
- Fail2Ban Logs
- Analyse von blockiertem Traffic

---

## 🧠 Bezug zur CompTIA Security+

Abgedeckte Themen:
- Network Security
- Secure Architecture
- Identity & Access Management
- Logging & Monitoring
- Defense in Depth
- Incident Detection
- Least Privilege

---

## 🚀 Geplante Erweiterungen

- SIEM (Wazuh / ELK)
- Active Directory Security (LAPS, Kerberoasting)
- Vulnerability Scanning (OpenVAS)
- MITRE ATT&CK Mapping
- Incident-Response-Szenarien

---

## 🏁 Fazit

Dieses HomeLab bildet eine realistische Enterprise-IT-Umgebung ab und demonstriert:

- strukturiertes Arbeiten
- Security-Mindset
- saubere Dokumentation
- praxisnahe System- & Netzwerksicherheit

