# Enterprise Home Lab & Security Infrastructure

## 🎯 Projektziel
Transformation eines Standard-Heimnetzwerks in eine professionelle, segmentierte Lab-Umgebung. Ziel ist die Vertiefung von Kenntnissen in Virtualisierung, Firewalling (pfSense) und Containerisierung (Docker/Kubernetes).

# 🛡️ Project-HomeLab: Proxmox Infrastructure

## 💻 Hardware-Stack
- **Hypervisor:** AOOSTAR WTR PRO (AMD Ryzen 7 5825U, 64GB RAM)
- **Router:** TP-Link Archer AX18
- **ISP:** Magenta Fiber Box (aktuell im Double-NAT Modus / DMZ geplant)
- **Extender:** TP-Link RE330 (OneMesh für Arbeitszimmer-Konnektivität)

## 📊 Status & Screenshots
### Proxmox Dashboard
![Dashboard](./img/Proxmox_Dashboard_CPU_RAM_Übersicht.png)

### Netzwerk-Konfiguration
![Netzwerk](./img/Netzwerk_Konfiguration.png)

## 🌐 Netzwerk-Topologie

```mermaid
graph TD
    subgraph "Internet"
        ISP[Magenta Fiber Box]
    end

    subgraph "Physische Infrastruktur"
        Archer[TP-Link Archer AX18 - 192.168.1.1]
        Aoostar[AOOSTAR WTR PRO - Proxmox Host]
    end

    subgraph "Virtuelle Umgebung (Proxmox)"
        WAN_Bridge((vmbr0 - WAN))
        LAN_Bridge((vmbr1 - Isoliertes LAN))
        
        pfSense[pfSense Firewall]
        Mint[Linux Mint Management VM]
    end

    ISP --- Archer
    Archer --- WAN_Bridge
    WAN_Bridge --- pfSense
    pfSense --- LAN_Bridge
    LAN_Bridge --- Mint

`````

### 📊 Proof of Concept
Hier ist die erfolgreiche Verbindung der Management-VM durch die Firewall dokumentiert:

![pfSense Dashboard](./img/pfsense_dashboard.jpg)
*Abbildung 1: Zentrales Management-Dashboard in pfSense.*

![Ping Test](./img/pfsense_ping.jpg)
*Abbildung 2: Erfolgreicher ICMP-Ping auf 8.8.8.8 zur Verifizierung der Internet-Konnektivität.*

| Komponente | Interface | IP-Adresse | Subnetzmaske | Zweck |
| :--- | :--- | :--- | :--- | :--- |
| **Archer Router** | LAN | `192.168.1.1` | `/24` | Physisches Gateway & WAN-Quelle |
| **pfSense** | WAN (`vmbr0`) | `192.168.1.136` | `/24` | Uplink zum Internet (via Archer) |
| **pfSense** | LAN (`vmbr1`) | `10.0.0.1` | `/24` | Standard-Gateway für das Lab |
| **Linux Mint** | ETH0 (`vmbr1`) | `10.0.0.10` | `/24` | Management-Client (Xfce Edition) |
| **Lab-Bereich** | DHCP-Pool | `10.0.0.100-200` | `/24` | Bereich für zukünftige Test-VMs |

### 🛡️ Security-Hardening: pfBlockerNG Integration (Abbildung 3)

Um das Netzwerk proaktiv gegen Telemetrie, Tracking und bösartige Domains abzusichern, wurde **pfBlockerNG-devel** implementiert. 

![pfBlockerNG Test](./img/pfsense_pfblocker_test.jpg)
*Abbildung 3: Erfolgreicher DNS-Blocking-Test. Die Domain "flurry.com" wird durch die Firewall abgefangen und auf die interne VIP 10.10.10.1 umgeleitet.*

#### Technische Highlights:
* **DNSBL-Filterung:** Automatisierte Blockierung von Werbe- und Tracking-Servern auf DNS-Ebene.
* **Validierung:** Der `nslookup`-Befehl bestätigt, dass der Filter aktiv in den Datenverkehr der Management-VM eingreift.
* **Ressourcen-Effizienz:** Dank der **Linux Mint 22.2 Xfce Edition** bleibt die Last auf dem Proxmox-Host minimal, wodurch mehr Kapazität für die umfangreichen Filter-Datenbanken der pfSense zur Verfügung steht.


### 🌐 Deployment des Web-Services (Abbildung 4)

Nach der Absicherung des Gateways wurde ein dedizierter Webserver auf Basis von **Debian 13 (Trixie)** implementiert. 

![Proxmox Management Übersicht](./img/pfsense_webserver_management.png)
*Abbildung 4: Zentrale Verwaltung in Proxmox. Die Übersicht zeigt die Koexistenz von Firewall, Management-VM und dem aktiven Apache-Webserver.*

#### Details zur Implementierung:
* **Infrastruktur:** Betrieb von drei spezialisierten VMs auf einem Proxmox-Node.
* **Service-Status:** Verifizierung des Apache2-Dienstes (`active/running`) direkt über die Proxmox-Konsole.
* **Effizienz-Faktor:** Durch die Nutzung der **Linux Mint 22.2 Xfce Edition** zur Administration bleibt die grafische Last minimal, was einen reibungslosen Parallelbetrieb aller Dienste ermöglicht.
 
## 🏗️ Infrastruktur-Komponente: Webserver-01

Im Rahmen des Laboraufbaus wurde ein dedizierter Webserver implementiert, der als Ziel für die Firewall-Regeln und Portweiterleitungen dient.

### Spezifikationen
* **Betriebssystem:** Debian 13.3 (Trixie), Netinst-Image (Stand 2026)
* **Ressourcen:** 1 vCPU, 512 MB RAM, 10 GB Disk
* **Netzwerk-Anbindung:** `vmbr1` (Internes LAN hinter pfSense)
* **IP-Konfiguration:** Statische Zuweisung (DHCP Static Mapping) auf `10.0.0.12`
* **Dienste:** Apache2 (HTTP), OpenSSH-Server

### Konfigurations-Details
Der Server wurde "headless" (ohne grafische Oberfläche) aufgesetzt, um die Performance des Proxmox-Hosts (Ryzen 7) zu maximieren. Die Verwaltung erfolgt effizient über die **Linux Mint 22.2 Xfce Edition**, was den Ressourcenverbrauch des Management-Clients minimal hält.

#### Verifizierung des Dienstes:

Um sicherzustellen, dass der Webdienst korrekt läuft, wurde der Status des Apache-Daemons abgefragt:

```bash
# 1. Befehl zur Statusabfrage
angel@webserver-01:~$ systemctl status apache2

# 2. Relevante Systemausgabe (Auszug)
● apache2.service - The Apache HTTP Server
     Loaded: loaded (/usr/lib/systemd/system/apache2.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-01-13 09:43:34 CET; 10min ago
     ...
     Main PID: 671 (apache2)
```
### 🛡️ Firewall & NAT: Externer Zugriff

Um den internen Webdienst sicher zu veröffentlichen, wurde eine Portweiterleitung (DNAT) auf der pfSense-Firewall konfiguriert. 

#### Konfiguration:
* **Eingehendes Interface:** WAN
* **Dienst:** HTTP (TCP Port 80)
* **Zielsystem:** 10.0.0.12 (Debian 13 Webserver)

![Abbildung 5: WAN Firewall Rules](./img/pfSense_WAN_Rule.jpg)
*Abbildung 5: Automatisch generierte Firewall-Regel nach erfolgreicher NAT-Konfiguration. Der Zugriff wird explizit nur für Port 80 auf das Zielsystem erlaubt.*

> **System-Performance:** Die Konfiguration wurde über die **Linux Mint Xfce Edition** validiert. Die Wahl dieses Desktops ermöglichte eine verzögerungsfreie Bedienung der pfSense-Weboberfläche, während die Firewall-Logs in Echtzeit analysiert wurden.

## 🔒 Security-Features & Implementierung

### 1. SSL/TLS Verschlüsselung
Der Apache-Webserver wurde mit `mod_ssl` gehärtet. Der Zugriff erfolgt verschlüsselt über Port 443, wobei pfSense den Traffic via Destination NAT (DNAT) direkt an den Debian-Endpunkt leitet.

### 2. Management-Isolation (Port-Remapping)
Um Sicherheitsrisiken und Port-Konflikte zu minimieren, wurde das Management-Interface der pfSense vom Standard-Port auf **Port 8443** verschoben. 
* **Ergebnis:** Port 80 und 443 stehen exklusiv für öffentliche Dienste zur Verfügung, während die Administration über einen gesicherten, nicht-standardisierten Kanal erfolgt.

### 3. Ressourcen-Optimierung
Durch den Einsatz der **Linux Mint Xfce Edition** zur Administration wurde die Systemlast auf dem Proxmox-Host minimiert. Dies ermöglicht eine performante Überwachung der Traffic-Graphen und Firewall-Logs in Echtzeit, selbst bei hoher Verschlüsselungslast auf dem Server.

## 🚦 Verifizierung der Dienste

| Dienst | Zugriff | Protokoll | Status |
| :--- | :--- | :--- | :--- |
| Webserver (Public) | `http://192.168.1.136` | HTTP (80) | ✅ Online |
| Webserver (Secure) | `https://192.168.1.136` | HTTPS (443) | ✅ Online |
| pfSense Admin | `https://10.0.0.1:8443` | HTTPS (8443) | ✅ Gesichert |

## 🏗️ Architektur & Topologie

- **Virtualisierungs-Host:** Proxmox VE (AMD Ryzen 7 5825U)
- **Firewall:** pfSense CE (WAN/LAN Segregation)
- **Management-Node:** Linux Mint 22.2 Xfce Edition
- **Service-Node:** Debian 13 "Bookworm" (Apache2 Webserver)

### Netzwerk-Spezifikationen
- **WAN IP (Lab):** 192.168.1.136
- **LAN Subnetz:** 10.0.0.0/24
- **Webserver-IP (Intern):** 10.0.0.12

## 🔒 Security & Konfiguration

### 1. Port-Remapping & Härtung
Um Port-Konflikte zu vermeiden und die Sicherheit zu erhöhen, wurde das pfSense-Management vom Standard-Port auf **Port 8443** verschoben. Dadurch bleiben die Ports 80/443 exklusiv für den öffentlichen Webserver reserviert.

### 2. NAT & Firewall-Regeln
Anfragen an das WAN-Interface werden via Destination NAT (DNAT) direkt an den Debian-Server geleitet. Die Regeln umfassen sowohl HTTP (80) als auch HTTPS (443).

![Firewall Regeln](./img/pfsense_wan_rules.jpg)
*Abbildung 1: Aktive Port-Forwarding-Regeln für den Webserver-Zugriff.*

## 🔄 Analyse: Internes vs. Externes Routing (NAT-Loopback)

Ein Kernaspekt dieses Projekts ist die korrekte Handhabung des Datenflusses je nach Ursprung der Anfrage:

* **Externer Zugriff (Physischer PC):** Die Anfrage auf `http://192.168.1.136` wird durch die NAT-Regel direkt zum Webserver geleitet.
* **Interner Zugriff (Management-VM):** Anfragen an die WAN-IP aus dem LAN führen zum Management-Interface der pfSense.

![Externer Zugriff](./img/external_access_debian.jpg)
*Abbildung 2: Erfolgreicher Zugriff von außen auf den Debian-Webserver.*

![Interner Zugriff](./img/internal_access_pfsense.jpg)
*Abbildung 3: Interner Zugriff auf das pfSense-Login über die LAN-Schnittstelle.*

> **Dokumentations-Fazit:** Dieses Verhalten belegt eine erfolgreiche **Netzwerk-Segmentierung**. Der administrative Zugriff ist logisch vom öffentlichen Dienst getrennt, was die Angriffsfläche des Systems minimiert.

## 📊 Monitoring & Performance

Die Verwaltung erfolgt über die ressourceneffiziente **Linux Mint Xfce Edition**, was eine verzögerungsfreie Analyse der Firewall-Logs in Echtzeit ermöglicht.

![pfSense Dashboard](./img/pfsense_dashboard_live.jpg)
*Abbildung 4: Zentrales Dashboard mit verifiziertem Zugriff über HTTPS auf Port 8443.*


## Einrichtung VLAN 20 (Webserver) & Security Hardening

### 1. Netzwerk-Segmentierung
Um den Webserver vom Management-Netz zu isolieren, wurde ein neues VLAN (ID 20) angelegt.
* **Interface:** WEBSERVER (VLAN 20 auf vtnet1)
* **IP-Adressbereich:** 10.0.20.1/24
* **DHCP-Range:** 10.0.20.50 - 10.0.20.100

![DHCP_Range](./img/DHCP-Einstellungen_Range_10.0.20.50-100.jpg)
*Abbildung 5: Definition des Adresspools für das WEBSERVER-Interface (VLAN 20) mit einer dynamischen Range von 10.0.20.50 bis 10.0.20.100.*

### 2. Firewall-Regelwerk & DMZ-Isolierung
Das Regelwerk wurde so konfiguriert, dass eine "Einweg-Kommunikation" herrscht. Das Management-VLAN (10) hat vollen Zugriff auf den Webserver, während der Webserver keinen Zugriff auf das Management-VLAN hat.

**Wichtigste Regeln auf dem WEBSERVER-Interface:**
1. **BLOCK:** Source: `WEBSERVER subnets` -> Destination: `LAN subnets` (Verhindert Angriffe vom Webserver auf Management-Clients).
2. **PASS:** Source: `WEBSERVER subnets` -> Destination: `any` (Erlaubt Internetzugriff für Updates).


![Firewall_Rules](./img/Firewall_Rules_WEBSERVER_subnets_Destination_LAN_subnets.png)
*Abbildung 6:Firewall-Regelwerk des Webserver-Interfaces mit einer priorisierten Block-Regel (Source: WEBSERVER subnets) zum Schutz des LAN-Segments (Destination: LAN subnets.*

### 3. Verifizierung der Konfiguration
Die erfolgreiche Einrichtung wurde durch folgende Tests bestätigt:
* **Connectivity:** Management-VM (10.0.10.50) kann Webserver (10.0.20.50) pingen.
* **Service:** Apache2 Default Page ist über den Browser im Management-Netz erreichbar.
* **Security:** Ping vom Webserver (10.0.20.50) zum Management (10.0.10.50) schlägt fehl (Request Timeout).

![Webserver_Isolierung_Verifikation](./img/DMZ_Isolierungstest_Fail.png)
*Abbildung 7:Erfolgreicher Nachweis der Netzisolierung durch einen fehlgeschlagenen Ping-Versuch (100% Paketverlust) von der Webserver-VM (10.0.20.50) in das Management-Netz (10.0.10.50).*

# Webserver DMZ Migration & Security Hardening

Erfolgreiche Migration des Debian-Webservers in eine isolierte **DMZ** zur Absicherung des LANs.

## 1. Webserver IP & Routing
Statische IP-Konfiguration in `/etc/network/interfaces`:
* **IP:** `10.0.30.50` | **Gateway:** `10.0.30.1`

![Screenshot_etc_network_interfaces](./img/schreenshot_etc_network_interfaces.png)
*Abbildung 8: Konfiguration der Netzwerkschnittstelle ens18 mit statischer IP 10.0.30.50 und DMZ-Gateway 10.0.30.1 in /etc/network/interfaces.*
![Screenshot_ip_a](./img/sscreenshot_ip_a.png)
*Abbildung 9: Validierung der aktiven Netzwerkkonfiguration mittels ip a zur Bestätigung der korrekten IP-Zuweisung im DMZ-Segment.*


---

## 2. pfSense: NAT & Firewall
Anpassung der WAN-Weiterleitung und Isolation der DMZ.

* **NAT:** Ports 80/443 auf `10.0.30.50` umgeleitet.
* **Firewall Regeln:** 1. **BLOCK** zu LAN Subnet (Isolation)
    2. **BLOCK** zu Webserver Subnet (Management-Schutz)
    3. **PASS** zu Any (Internet für Updates)

![screenshot_port_forwarding](./img/screenshot_port_forwarding.png)
*Abbildung 10: pfSense NAT-Port-Forwarding: Umleitung von externem HTTP/HTTPS-Traffic (Port 80/443) auf die interne Webserver-IP 10.0.30.50.*

![screenshot_dmz_firewall_rules](./img/ss11_dmz_firewall_rules.png)
*Abbildung 11: DMZ-Firewall-Regelsatz zur strikten Isolation: Blockierung von Zugriffen auf LAN und Management-Netz bei gleichzeitigem Erlauben von ausgehendem Internet-Traffic.*

---

## 3. Verifizierung & Sicherheitstests
Nachweis der korrekten Funktion und Netzwerktrennung:

* **Erfolg:** Webserver via WAN erreichbar (Apache Default Page).
* **Erfolg:** Internet-Ping (`8.8.8.8`) funktioniert.
* **Sicherheit:** LAN-Ping (`10.0.10.1`) blockiert (**100% Packet Loss**).

![Screenshot_apache_WAN_migration](./img/ss12_apache_WAN_migration.png)
*Abbildung 12:Erfolgreicher Funktionstest des Webservers über die WAN-Schnittstelle (192.168.1.136) nach Migration in die DMZ.*
![Screenshot_connection_test](./img/ss13_connection_test.png)
*Abbildung 13: Konnektivitätsprüfung: Erfolgreicher Ping ins Internet (8.8.8.8) und verifizierte Blockierung (Destination Host Unreachable) zum geschützten LAN-Segment.*

---
## 🔐 SSH-Security & Hardening

Um den administrativen Zugriff auf den Webserver-01 abzusichern, wurden spezifische Sicherheitsmaßnahmen in der SSH-Konfiguration (`/etc/ssh/sshd_config`) vorgenommen.

### 1. Deaktivierung des Root-Logins
Der direkte Login als `root` wurde unterbunden, um Angreifern das höchstprivilegierte Ziel zu entziehen. Administratoren müssen sich als regulärer User (`angel`) anmelden und bei Bedarf `sudo` nutzen.

### 2. Erzwingen von SSH-Keys
Die Authentifizierung wurde so konfiguriert, dass sie idealerweise über kryptografische Schlüsselpaare (SSH-Keys) erfolgt, was weitaus sicherer ist als herkömmliche Passwörter.

### 3. Protokollierung und Überwachung
In Kombination mit Fail2Ban werden alle fehlgeschlagenen SSH-Login-Versuche protokolliert und führen nach mehrmaligem Scheitern zur automatischen Sperrung der IP-Adresse.

![Screenshot_ss23_permitrootlogin_no](./img/ss23_permitrootlogin_no.png)
*Abbildung 14: Auszug der SSH-Konfigurationsdatei mit der aktiven Richtlinie PermitRootLogin no zur Erhöhung der Systemsicherheit.*

---

## 🛡️ Server-Sicherheit: Fail2Ban Schutz

Um den Webserver gegen automatisierte Brute-Force-Angriffe (z. B. auf SSH) zu schützen, wurde der Dienst **Fail2Ban** installiert und konfiguriert.

### 1. Installation und Funktionsweise
Fail2Ban überwacht die Logfiles des Systems auf verdächtige Anmeldeversuche. Nach einer definierten Anzahl an Fehlversuchen wird die IP-Adresse des Angreifers automatisch über die Firewall gesperrt.

**Installation:**
```bash
sudo apt update && sudo apt install fail2ban -y
```


## 🗄️ Datenbank-Setup & PHP-Anbindung

In diesem Abschnitt wurde die MariaDB-Datenbank konfiguriert und eine Test-Schnittstelle mit PHP geschaffen.

### 1. MariaDB Installation & Absicherung
Die Datenbank wurde mit `mariadb-secure-installation` gehärtet.
![Screenshot_mariadb_secure_installation](./img/ss14_mariadb_secure_installation.png)
*Abbildung 14.5: Erstmalige Anmeldung und Initialisierung der MariaDB-Konsole auf dem Webserver-01.*



### 2. Datenbank und Benutzer erstellen
Folgende SQL-Befehle wurden ausgeführt, um die Projekt-Datenbank und den dedizierten Web-User anzulegen:

```sql
-- Datenbank erstellen
CREATE DATABASE projekt_db;

-- Benutzer mit eingeschränkten Rechten anlegen
CREATE USER 'webuser'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON projekt_db.* TO 'webuser'@'localhost';
FLUSH PRIVILEGES;
```



![Screenshot_datenbank_user_erstellen](./img/ss15_datenbank_user_erstellen.png)
*Abbildung 15: SQL-Befehlskette zur Erstellung der Datenbank projekt_db sowie die Einrichtung des Datenbank-Benutzers webuser mit den entsprechenden Berechtigungen.*



### 3. PHP-Schnittstelle (db_test.php)

![Screenshot_db_test_nano](./img/ss16_db_test_nano.png)
*Abbildung 16: Implementierung des PHP-Verbindungsskripts db_test.php im Texteditor Nano zur Verknüpfung von Webserver und Datenbank-Backend.*
![Screenshot_datenbank_webseite](./img/ss17_datenbank_webseite.png)
*Abbildung 17: Erfolgreicher Validierungstest im Webbrowser der Mint-Management-VM, der die aktive Kommunikation zwischen PHP und der MariaDB-Instanz bestätigt.*


# Dokumentation Phase 2: Aufbau des interaktiven Web-Services

## 1. System-Übersicht (LAMP-Stack)
Im Zeitraum von Tag 16 bis 22 wurde ein statischer Webserver in einen vollwertigen Application-Stack umgewandelt:
* **Linux:** Ubuntu Server (Webserver-01) in der DMZ (10.0.30.50).
* **Apache:** Webserver-Dienst mit SSL/TLS.
* **MariaDB:** Relationales Datenbanksystem.
* **PHP:** Backend-Logik.

> **Screenshot-Beleg: Die fertige Web-Oberfläche mit Einträgen**
> ![Web-Oberfläche](/img/webseite_Einträge.png)
> *Abbildung 18: Die Web-Oberfläche mit Einträge.*

---

## 2. Datenbank-Design & Sicherheit
Es wurde eine Datenbank `projekt_db` mit der Tabelle `logbuch` erstellt.
* **Schema:** `id`, `eintrag`, `zeitpunkt`, `bild`.
* **Security:** Verwendung von **Prepared Statements** gegen SQL-Injection.

> ![Datenbank-Struktur](/img/screenshot_mariadb2.png)
> *Abbildung 19: Tabellenstruktur in MariaDB (DESCRIBE logbuch;)*

---

## 3. Implementierte Kern-Funktionen (CRUD)
* **Create/Read:** Formular für Text und Datei-Uploads (Bilder).
* **Delete:** Löschen von Einträgen über IDs.
* **Auth:** Passwortschutz mittels PHP-Sessions.

> ![PHP-Code](/img/schreenshot_code_log_php.png)
> *Abbildung 20: PHP-Code der Login- oder Upload-Logik*

---

## 4. Netzwerk- & Infrastruktur-Konfiguration
* **Verschlüsselung:** Einbindung eines selbstsignierten SSL-Zertifikats.
* **Troubleshooting:** Korrektur der `000-default.conf` (AllowOverride) und DNS-Fix.

> ![HTTPS-Check](/img/meme_leonardo.png)
> *Abbildung 21: Erfolgreicher Apache-Neustart und HTTPS-Schloss im Browser*

---


# IT-Dokumentation: Phase 3 - Monitoring & Automatisierung

Dieses Dokument beschreibt die Planung und Implementierung eines automatisierten Sicherungsverfahrens für das Projekt "Foto-Logbuch". Als Systemadministrator ist es mein Ziel, die Datenintegrität durch regelmäßige Backups sicherzustellen.

---

## 1. Vorbereitung der Backup-Infrastruktur
Um die Datensicherheit zu gewährleisten, wurde ein dediziertes Verzeichnis erstellt. Dieses liegt außerhalb des Web-Wurzelverzeichnisses, um einen unbefugten Zugriff über den Browser zu verhindern.

* **Befehle:** - `mkdir -p /home/angel/backups` (Erstellen des Ordners)
  - `chmod 700 /home/angel/backups` (Rechtevergabe: Nur Besitzer darf lesen/schreiben)
* **Ziel:** Schutz der SQL-Dumps vor anderen Systemnutzern.

> **Beleg: Verzeichnisstruktur und Berechtigungen**
> ![Backup Verzeichnis Setup](./img/Screenshot_Verzeichnis.png)
> *Abbildung 22: Das Verzeichnis *


---

## 2. Implementierung der Backup-Logik (Bash-Skript)
Es wurde ein Bash-Skript (`/home/angel/backup_logbuch.sh`) entwickelt, das den Export der Datenbank und die Komprimierung der Mediendateien übernimmt.

### Kernfunktionen des Skripts:
1. **Variablen:** Nutzung von `$DATUM` für eindeutige Dateinamen.
2. **Datenbank-Sicherung:** Export mittels `mysqldump` in eine `.sql` Datei.
3. **Datei-Archivierung:** Packen des `/var/www/html/uploads` Ordners mit `tar -czf`.
4. **Log-Rotation:** Automatisches Löschen von Dateien, die älter als 7 Tage sind (`find -mtime +7 -delete`).

> **Beleg: Vollständiger Quellcode des Skripts**
> ![Bash Skript Code](./img/Screenshot_Backup_Code.png)

---

## 3. Validierung und Funktionstest
Nach der Erstellung wurde das Skript manuell ausgeführt, um die korrekte Arbeitsweise zu verifizieren.

* **Test-Befehl:** `bash /home/angel/backup_logbuch.sh`
* **Ergebnis:** Das System erzeugt korrekte Dateigrößen (SQL-Dump im KB-Bereich, Bilder-Archiv im MB-Bereich).

> **Beleg: Erfolgreicher manueller Testlauf**
> ![Backup Validierung](./img/Screenshot_backup_validierung.png)

---

## 4. System-Automatisierung (Cronjob)

Um den Administrator zu entlasten, wurde der Prozess über den System-Scheduler `cron` automatisiert.

* **Zeitplan:** Täglich um 03:00 Uhr nachts.
* **Konfiguration:** `0 3 * * * /bin/bash /home/angel/backup_logbuch.sh`

> **Beleg: Eintrag in der Crontab**
> ![Crontab Konfiguration](./img/Screenshot_crontab_l.png)

---

## 5. Recovery-Szenario (Wiederherstellung)
Ein Backup ist nur nützlich, wenn die Wiederherstellung funktioniert. Ein simulierter Datenverlust wurde erfolgreich durch den Re-Import der SQL-Datei behoben.

* **Wiederherstellungs-Befehl:** `sudo mariadb -u root projekt_db < /home/angel/backups/db_backup_X.sql`


##### Containerisierung und Migration

In dieser Phase wurde die Anwendung von einer klassischen Host-Installation in eine moderne Microservice-Architektur mittels Docker überführt.

---

## 4.1 Infrastruktur-Setup (Docker Compose)
Die Umgebung wurde mit `docker-compose` definiert, um eine strikte Trennung zwischen Webserver (PHP) und Datenbank (MariaDB) zu gewährleisten.

> ![Screenshot der docker-compose.yml einfügen](./img/docker-compose-yml.png)
> *Abbildung 1: Konfiguration der Container-Infrastruktur inkl. Port-Mapping (8080:80) und Bind-Mounts für die Datenpersistenz.*

---

## 4.2 Custom Image Build (Dockerfile)
Da das Standard-PHP-Image keine MySQL-Treiber enthält, wurde ein eigenes Image erstellt.

* **Troubleshooting:** Ein anfänglicher Build-Fehler (Tippfehler `myysqli`) wurde erfolgreich identifiziert und korrigiert.
* **Lösung:** Anpassung des Dockerfiles und anschließender Re-Build des Images.

> ![Screenshot vom Terminal mit dem korrigierten Build einfügen](./img/Costum_image_build.png)
> *Abbildung 2: Erfolgreicher Build des Custom-PHP-Images nach Korrektur der mysqli-Erweiterungsinstallation.*

---

## 4.3 Datenbank-Migration und Troubleshooting
Der schwierigste Teil war der Umzug der Daten aus Phase 3 in den neuen Docker-Container.

### Problemstellung: Persistenz der Initialwerte
Nachträgliche Änderungen des `MYSQL_ROOT_PASSWORD` in der Compose-Datei wurden vom Container ignoriert, da das Daten-Volume bereits mit dem Initial-Passwort erstellt worden war.

### Lösungsweg:
1. Löschen des persistenten Ordners `./db_data`.
2. Neuinitialisierung des Containers mit dem Passwort `123`.
3. Import des SQL-Dumps über die Standard-Eingabe in den Container.

> ![Screenshot vom Terminal mit dem erfolgreichen Import-Befehl einfügen](./img/Docker_Datenbank_Migration.png)
> *Abbildung 3: Erfolgreicher Datenimport des Backups in den laufenden MariaDB-Container unter Verwendung des Passworts '123'.*

---

## 4.4 Finaler Funktions-Test
Nach dem Abgleich der Anmeldedaten in der `db_test.php` (Passwort: `123`, Host: `db`) konnte die erfolgreiche Verbindung bestätigt werden.

> ![Screenshot vom Browser mit der grünen Erfolgsmeldung einfügen](./img/MariaDB_Container_Browser.png)
> *Abbildung 4: Web-Frontend bestätigt die erfolgreiche Kommunikation zwischen PHP-Container und MariaDB-Container im Docker-Netzwerk.*

---

## 4.5 Fazit Phase 4
Durch die Containerisierung ist die Applikation nun plattformunabhängig, leicht skalierbar und durch die Trennung von Code und Daten wesentlich sicherer. Die Fehlerbehebung während der Migration hat das Verständnis für Docker-Volumes und Netzwerk-Kommunikation vertieft.


# Dokumentation Phase 5: Client-Provisionierung & Domänenintegration

## 1. Zielsetzung
Ziel dieser Phase war die Bereitstellung eines Windows 11 Pro Clients (**CL-01-WIN11**), die Installation notwendiger Treiber für die virtualisierte Umgebung (Proxmox) sowie die vollständige Integration in die Active Directory Domäne `projekt.local`.

---

## 2. VM-Konfiguration (Proxmox)
Für eine optimale Performance und Kompatibilität mit Windows 11 wurden folgende Hardware-Parameter gewählt:

* **CPU:** 2 Cores (Host-Typ für maximale Befehlssatz-Unterstützung).
* **RAM:** 4 GiB DDR4.
* **BIOS:** OVMF (UEFI) mit dediziertem EFI-Disk.
* **Sicherheit:** Virtueller TPM-Chip (v2.0) zur Erfüllung der Windows 11 Anforderungen.
* **Disk:** 64 GB über **VirtIO SCSI single** Controller (mit *Discard*-Option für SSD-Optimierung).
* **Netzwerk:** Virtuelle Bridge `vmbr1` mit **VLAN-Tag 30** zur Trennung des Client-Netzwerks.

---

## 3. Betriebssystem-Installation & Treiber
Die Installation von Windows 11 Pro erforderte aufgrund der gewählten VirtIO-Hardware spezifische Schritte:

1.  **Treiber-Einbindung:** Da Windows standardmäßig keine VirtIO-SCSI-Treiber besitzt, wurde das `virtio-win.iso` eingebunden. Während des Setups wurde der Treiber aus dem Pfad `vioscsi\w11\amd64` geladen, um die Festplatte zu erkennen.
2.  **Umgehung des Online-Zwangs:** Mittels des Befehls `OOBE\BYPASSNRO` in der CMD (Shift+F10) wurde die Installation eines lokalen Kontos ohne Microsoft-Account ermöglicht.
3.  **Post-Installation:** Nach dem ersten Login wurden die `Guest Tools` installiert, um Netzwerk- (VirtIO-Net) und Grafikkartentreiber zu aktualisieren.

---

## 4. Netzwerk-Konfiguration & Domänenbeitritt
Um die Kommunikation mit dem Domain Controller (**DC-01**) sicherzustellen, wurde eine statische IP-Konfiguration vorgenommen:

* **IP-Adresse:** `10.0.30.20`
* **Subnetzmaske:** `255.255.255.0`
* **Standardgateway:** `10.0.30.1`
* **Bevorzugter DNS:** `10.0.30.100` (DC-01)

Nach erfolgreichem Ping-Test auf `projekt.local` wurde der Client über die Systemeigenschaften der Domäne hinzugefügt. Die Authentifizierung erfolgte über den administrativen Account `a.admin`.

> ![Screenshot Windows Systemeigenschaften](./img/Systemeigenschaften.png)
> *(Zeigt die Meldung "Willkommen in der Domäne projekt.local" oder den vollständigen Computernamen CL-01-WIN11.projekt.local)*

---

## 5. Active Directory Verwaltung & Gruppenrichtlinien (GPO)
Nach dem Beitritt wurde das Computer-Objekt im AD-Manager vom Standard-Container `Computers` in die organisationsspezifische OU `Angel_Projekt -> Computer` verschoben.

Zur Überprüfung der zentralen Steuerung wurde die Richtlinie **GPO_Sicherheit_Login** erstellt und mit der OU verknüpft. Diese konfiguriert eine interaktive Anmeldung mit einem rechtlichen Hinweis (Banner).

* **Einstellung:** *Interaktive Anmeldung: Nachrichtentext & Titel*
* **Überprüfung:** Mittels `gpupdate /force` am Client wurde die Übernahme erzwungen.

> ![Screenshot Active Directory Benutzer und Computer](./img/CL-01-WIN11_AD.png)
> *(Zeigt CL-01-WIN11 innerhalb der Unter-OU "Computer")*

> ![Screenshot Der "HINWEIS"-Banner beim Client-Start](./img/Willkommen_Hinweis.png)
> *(Der finale Beweis: Die Nachricht "Willkommen im gesicherten Bereich..." erscheint auf dem Client)*

---

## 6. Fazit Phase 5
Der Client ist nun vollständig im Management-Bereich des Servers. Die Namensauflösung (DNS) und die Sicherheitsrichtlinien (GPO) funktionieren einwandfrei. Das System ist bereit für die Bereitstellung von Netzwerkressourcen.

### Phase 6 & 7: Zentraler Fileserver & Datensicherheit

## 1. Zielsetzung
Aufbau einer zentralen Dateiablage auf dem Domain Controller (**DC-01**), um Projektdaten strukturiert bereitzustellen. Ziel ist der automatisierte Zugriff für Domänen-Benutzer sowie die Absicherung gegen versehentliches Löschen.

---

## 2. Einrichtung der Freigabe & Berechtigungen
Die Berechtigungen wurden nach dem **AGDLP-Prinzip** (Account, Global Group, Domain Local Group, Permission) konfiguriert. 

* **Physischer Pfad:** `C:\Shares\Projektdaten` auf dem Server DC-01.
* **Sicherheitsgruppe:** Erstellung der AD-Gruppe `G_Projekt_Vollzugriff`.
* **NTFS-Rechte:** Die Gruppe erhielt die Berechtigungen "Ändern", "Lesen" und "Schreiben".
* **Freigabe-Rechte:** "Authentifizierte Benutzer" erhielten Vollzugriff auf Ebene der Freigabe, während die tatsächliche Steuerung über die NTFS-Sicherheit erfolgt.

> ![Screenshot Ordner-Eigenschaften von 'Projektdaten' -> Reiter Sicherheit (NTFS)](./img/NTFS-Berechtigungen.png)
> *(Zeigt die Gruppe G_Projekt_Vollzugriff mit den gesetzten Haken)*

---

## 3. Automatisierung per Gruppenrichtlinie (GPO)
Um den Benutzerkomfort zu erhöhen, wurde die Richtlinie `GPO_DriveMapping_P` erstellt. Diese sorgt dafür, dass das Netzlaufwerk bei der Anmeldung automatisch verbunden wird.

* **Konfigurationspfad:** `Benutzerkonfiguration` > `Einstellungen` > `Windows-Einstellungen` > `Laufwerkszuordnungen`.
* **Parameter:** * Aktion: Aktualisieren
    * Pfad: `\\DC-01\Projektdaten`
    * Laufwerkbuchstabe: **P:**

>![Screenshot GPO-Editor mit der Konfiguration der Laufwerkszuordnung](./img/GPO_Laufwerkszuordnung.png)
> *(Zeigt das Fenster, in dem der Pfad \\DC-01\Projektdaten und der Buchstabe P konfiguriert sind)*

---

## 4. Validierung am Client (Windows 11)
Der Erfolg der Konfiguration wurde am Client **CL-01-WIN11** mit dem Benutzer `a.admin` verifiziert. 

1. Erzwungenes Update der Richtlinien via `gpupdate /force`.
2. Automatische Einbindung des Laufwerks **P:** im Datei-Explorer.
3. Erfolgreicher Schreib- und Lesetest (Erstellung einer Testdatei).

>![Screenshot Der kombinierte Screenshot von CL-01-WIN11](./img/Client-Validierung.png)
> *(Zeigt die CMD mit gpupdate /force und den Explorer mit dem Laufwerk Projektdaten (P:))*

---

## 5. Datensicherheit: Schattenkopien (VSS)
Als zusätzliche Sicherheitsmaßnahme wurden **Schattenkopien (Volume Shadow Copies)** auf dem Server-Volume aktiviert.

* **Funktion:** Regelmäßige Snapshots des Dateisystems.
* **Nutzen:** Benutzer können über den Reiter "Vorgängerversionen" gelöschte oder überschriebene Dateien ohne Admin-Eingriff selbstständig wiederherstellen.

> ![Screenshot Schattenkopien-Einstellungen auf DC-01](./img/Schattenkopien.png)
> *(Zeigt das Fenster "Schattenkopien" mit dem Status "Aktiviert" für Laufwerk C:)*

---

## 6. Fazit
Mit Abschluss dieser Phase verfügt die Domäne über einen voll funktionsfähigen Fileserver. Die Kombination aus GPO-basierter Laufwerkszuordnung und Schattenkopien bietet eine benutzerfreundliche und zugleich sichere Arbeitsumgebung.

# Dokumentation Phase 8: Fortgeschrittene Administration & Monitoring

## 1. Zielsetzung
In dieser Phase wurde der Fileserver (DC-01) gegen unkontrolliertes Datenwachstum abgesichert und ein proaktives Monitoring-System für Systemereignisse etabliert. Ziel ist es, die Systemstabilität zu gewährleisten und die Einhaltung von Unternehmensrichtlinien (z. B. Verbot privater Daten auf Projektlaufwerken) technisch zu erzwingen.

---

## 2. Speicherplatz-Management (Quotas)
Um zu verhindern, dass ein einzelner Benutzer die gesamte Festplattenkapazität des Servers beansprucht, wurde ein Kontingentmanagement eingeführt.

* **Werkzeug:** Ressourcenmanager für Dateiserver (FSRM).
* **Konfiguration:** * **Pfad:** `C:\Shares\Projektdaten`
    * **Limit:** 5 GB (Hartes Kontingent - verhindert weiteres Speichern bei Erreichen des Limits).
    * **Vorlage:** Eigens erstellte Vorlage `Limit_5GB_Projektdaten`.

> ![Screenshot 'Kontingent erstellen' - zeigt den Pfad und die 5GB Auswahl](./img/Kontingent-Konfiguration.png)

---

## 3. Schwellenwerte & Benachrichtigung
Damit Engpässe frühzeitig erkannt werden, wurde ein Warnsystem konfiguriert.

* **Schwellenwert:** Bei einer Belegung von **85 %** (ca. 4,25 GB) wird eine Aktion ausgelöst.
* **Protokollierung:** Da in der isolierten Testumgebung kein SMTP-Server für E-Mails existiert, wurde die Warnung auf das Windows-Ereignisprotokoll umgeleitet.
* **Meldungstext:** *"Warnung: Das Projektlaufwerk P ist zu 85% voll."*

> ![Screenshot 'Schwellenwert hinzufügen' - zeigt die 85% und die SMTP-Warnmeldung von Windows](./img/Schwellenwert_SMTP-Hinweis.png)

---

## 4. Dateiscreening (Inhaltsschutz)
Zum Schutz der beruflichen Nutzung des Netzlaufwerks wurde ein Dateiscreening implementiert, das das Speichern privater Medienformate unterbindet.

* **Konfiguration:** Aktives Screening für den Ordner `Projektdaten`.
* **Regel:** Blockieren der Dateigruppen "Bilddateien" (z. B. .jpg, .png) und "Audiodateien".
* **Wirkung:** Der Server verweigert das Schreiben dieser Dateitypen unabhängig von den NTFS-Benutzerrechten.

> ![Screenshot 'Dateiprüfungseigenschaften' - zeigt die aktiven Haken bei Bilddateien](./img/Dateiprüfungs-Eigenschaften.png)

---

## 5. Validierung am Client und Monitoring-Erfolg
Die Wirksamkeit der Maßnahmen wurde erfolgreich am Client **CL-01-WIN11** sowie im Server-Log nachgewiesen.

### A. Client-Test (Dateiprüfung)
Beim Versuch, eine Bilddatei in das Laufwerk **P:** zu kopieren, gibt Windows eine Fehlermeldung aus ("Zugriff verweigert"). Dies bestätigt die korrekte Funktion des FSRM-Dienstes.

> ![Screenshot Fehlermeldung am Client 'Zugriff auf den Zielordner wurde verweigert'](./img/Client-Test.png)

### B. Server-Überwachung (Ereignisanzeige)
Auf dem **DC-01** dokumentiert die Ereignisanzeige unter dem Protokoll "Anwendung" (Quelle: `SRMSVC`) alle Kontingentereignisse. Dies ermöglicht dem Administrator eine nachträgliche Auswertung der Speicherauslastung.

> ![Screenshot Ereignisanzeige auf DC-01 mit den SRMSVC-Einträgen](./img/Ereignisanzeige_Monitoring.png)

---

## 6. Projektsicherung
Nach Abschluss der Konfiguration und erfolgreicher Validierung wurden Snapshots beider virtueller Maschinen in Proxmox erstellt.

* **Snapshot-Name:** `Phase_8_Final_Admin_Monitoring`
* **Status:** System voll funktionsfähig und dokumentiert.



# Dokumentation Phase 9: Web-Infrastruktur & Netzwerk-Segmentierung

## 1. Zielsetzung
Das Ziel dieser Phase war die Migration des Webservers in ein isoliertes Server-VLAN (VLAN 20) und die Absicherung des Zugriffs nach dem **Least-Privilege-Prinzip**. Es sollte sichergestellt werden, dass Clients nur auf notwendige Dienste (HTTP) zugreifen können, während administrative Zugriffe (SSH) auf das Management-Netz beschränkt bleiben.

---

## 2. Netzwerk-Konfiguration & Migration
Der Webserver wurde von VLAN 30 in das neue **VLAN 20 (WEBSERVER)** verschoben.

* **IP-Adresse:** `10.0.20.50` (Statisch konfiguriert)
* **Subnetzmaske:** `255.255.255.0`
* **Standard-Gateway:** `10.0.20.1` (pfSense Interface)

> ![Screenshot Datei /etc/network/interfaces oder Befehl 'ip a' vom Webserver](./img/webserver_neue_ip_adresse.png)

---

## 3. Firewall-Härtung (pfSense)
Die Sicherheitsstrategie wurde von einer offenen "Allow-All"-Konfiguration auf eine restriktive "Whitelist"-Strategie umgestellt. 

### 3.1 Regeln im LAN-Interface (Management)
* **SSH (Port 22):** Erlaubt den administrativen Zugriff von der Linux Mint Management-Station auf den Webserver.
* **HTTP (Port 80):** Erlaubt den Zugriff auf den Webdienst zu Testzwecken.

### 3.2 Regeln im DMZ-Interface (Windows-Client)
* **HTTP-Only:** Dem Windows-Client wurde oberhalb der Block-Regeln explizit nur der Zugriff auf `10.0.20.50` über Port 80 erlaubt.
* **Isolation:** Die "Default Allow"-Regel wurde deaktiviert. Alle anderen Zugriffe (z.B. Ping oder Zugriff auf das Management-VLAN) werden nun durch die Firewall verworfen.

> ![Screenshot Datei Deine pfSense Rules im DMZ-Tab (mit der aktiven Port 80 Regel)](./img/pfsense_DMZ_Rules.png)

---

## 4. Bereitstellung des Webdienstes
Auf dem System (Debian) wurde ein LAMP-Stack (hier: Apache2) installiert und konfiguriert.

* **Dienst-Status:** Apache2 wurde erfolgreich gestartet und als "active (running)" verifiziert.
* **Personalisierung:** Die `index.html` wurde angepasst, um die erfolgreiche Migration und den Status des Projekts (LAMP-Stack online) anzuzeigen.

> ![Screenshot Datei Terminal mit dem Befehl 'systemctl status apache2'](./img/Webseite_test_Win_Client.png)


---
## 5. Validierung & Tests
Zur Bestätigung der korrekten Firewall-Konfiguration wurden folgende Tests durchgeführt:

| Testfall | Erwartetes Ergebnis | Status |
| :--- | :--- | :--- |
| HTTP-Zugriff von Win-11 (VLAN 30) | Webseite wird geladen | **Erfolgreich** |
| SSH-Zugriff von Mint (VLAN 10) | Login möglich | **Erfolgreich** |
| Ping von Win-11 zu Webserver | Zeitüberschreitung (Blockiert) | **Erfolgreich** |

> ![Screenshot Die personalisierte Webseite im Browser des Windows-Clients](./img/Cmd_win_client_ping_webserver.png)


# Dokumentation Phase 10: DNS & Namensauflösung

## 1. Zielsetzung
Implementierung einer benutzerfreundlichen Namensauflösung für den isolierten Webserver.

## 2. DNS-Konfiguration (pfSense)
In den Services des DNS-Resolvers wurde ein **Host Override** für den FQDN `webserver.home.arpa` auf die Ziel-IP `10.0.20.50` angelegt.

## 3. Firewall-Anpassung
Um die Kommunikation mit dem DNS-Dienst zu ermöglichen, wurde im DMZ-Interface eine Regel für **UDP Port 53** erstellt. Dies ist notwendig, da nach dem "Least Privilege"-Prinzip zuvor alle nicht explizit erlaubten Dienste blockiert wurden.

## 4. Client-Konfiguration
Der Windows-Client wurde so konfiguriert, dass er die pfSense (`10.0.30.1`) als primären DNS-Server nutzt.
> ![Screenshot Netzwerkeinstellungen geänderte IP-Adresse](./img/win_client_netzwerkeinstellungen_ipadresse.png)
## 5. Validierung
Die erfolgreiche Auflösung wurde mittels `nslookup` und durch den Aufruf der URL im Browser bestätigt.

> ![Screenshot Browser mit URL webserver.home.arpa](./img/browser_webserver_client_test.png)

