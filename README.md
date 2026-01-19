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

<img width="959" height="415" alt="Screenshot_etc_network_interfaces" src="https://github.com/user-attachments/assets/267b20bc-2373-4725-af24-eed550158dd5" />
*Abbildung 8: Konfiguration der Netzwerkschnittstelle ens18 mit statischer IP 10.0.30.50 und DMZ-Gateway 10.0.30.1 in /etc/network/interfaces.*
<img width="959" height="427" alt="Screenshot_ip_a" src="https://github.com/user-attachments/assets/0ae4914d-57c0-4734-9480-2525d379704d" />
*Abbildung 9: Validierung der aktiven Netzwerkkonfiguration mittels ip a zur Bestätigung der korrekten IP-Zuweisung im DMZ-Segment.*


---

## 2. pfSense: NAT & Firewall
Anpassung der WAN-Weiterleitung und Isolation der DMZ.

* **NAT:** Ports 80/443 auf `10.0.30.50` umgeleitet.
* **Firewall Regeln:** 1. **BLOCK** zu LAN Subnet (Isolation)
    2. **BLOCK** zu Webserver Subnet (Management-Schutz)
    3. **PASS** zu Any (Internet für Updates)

<img width="1916" height="838" alt="Screenshot 2026-01-15 142722" src="https://github.com/user-attachments/assets/2da15d35-370f-47da-a2db-7a53ac52226b" />
*Abbildung 10:pfSense NAT-Port-Forwarding: Umleitung von externem HTTP/HTTPS-Traffic (Port 80/443) auf die interne Webserver-IP 10.0.30.50.*

<img width="1919" height="838" alt="Screenshot 2026-01-15 142858" src="https://github.com/user-attachments/assets/435e4d16-f946-4a3f-9887-abe0f286584a" />
*Abbildung 11: DMZ-Firewall-Regelsatz zur strikten Isolation: Blockierung von Zugriffen auf LAN und Management-Netz bei gleichzeitigem Erlauben von ausgehendem Internet-Traffic.*

---

## 3. Verifizierung & Sicherheitstests
Nachweis der korrekten Funktion und Netzwerktrennung:

* **Erfolg:** Webserver via WAN erreichbar (Apache Default Page).
* **Erfolg:** Internet-Ping (`8.8.8.8`) funktioniert.
* **Sicherheit:** LAN-Ping (`10.0.10.1`) blockiert (**100% Packet Loss**).

<img width="1919" height="1079" alt="Screenshot 2026-01-15 143205" src="https://github.com/user-attachments/assets/8aecd844-0697-412d-b0f2-b3c68c6f15e7" />
*Abbildung 12:Erfolgreicher Funktionstest des Webservers über die WAN-Schnittstelle (192.168.1.136) nach Migration in die DMZ.*

<img width="1918" height="814" alt="Screenshot 2026-01-15 143440" src="https://github.com/user-attachments/assets/9dac9763-2e37-4616-8b1b-186768685a15" />
*Abbildung 13: Konnektivitätsprüfung: Erfolgreicher Ping ins Internet (8.8.8.8) und verifizierte Blockierung (Destination Host Unreachable) zum geschützten LAN-Segment.*

---
*Konfiguriert am 15.01.2026*

## 🔐 SSH-Security & Hardening

Um den administrativen Zugriff auf den Webserver-01 abzusichern, wurden spezifische Sicherheitsmaßnahmen in der SSH-Konfiguration (`/etc/ssh/sshd_config`) vorgenommen.

### 1. Deaktivierung des Root-Logins
Der direkte Login als `root` wurde unterbunden, um Angreifern das höchstprivilegierte Ziel zu entziehen. Administratoren müssen sich als regulärer User (`angel`) anmelden und bei Bedarf `sudo` nutzen.

### 2. Erzwingen von SSH-Keys
Die Authentifizierung wurde so konfiguriert, dass sie idealerweise über kryptografische Schlüsselpaare (SSH-Keys) erfolgt, was weitaus sicherer ist als herkömmliche Passwörter.

### 3. Protokollierung und Überwachung
In Kombination mit Fail2Ban werden alle fehlgeschlagenen SSH-Login-Versuche protokolliert und führen nach mehrmaligem Scheitern zur automatischen Sperrung der IP-Adresse.

<img width="1919" height="847" alt="Screenshot 2026-01-17 160917" src="https://github.com/user-attachments/assets/a1931520-70d2-4022-8670-8f087c7f176d" />
*Abbildung 23: Auszug der SSH-Konfigurationsdatei mit der aktiven Richtlinie PermitRootLogin no zur Erhöhung der Systemsicherheit.*

---

**Abbildung 23:** Auszug aus der SSH-Konfigurationsdatei, der die Sicherheitsanpassungen wie `PermitRootLogin no` verdeutlicht.

## 🛡️ Server-Sicherheit: Fail2Ban Schutz

Um den Webserver gegen automatisierte Brute-Force-Angriffe (z. B. auf SSH) zu schützen, wurde der Dienst **Fail2Ban** installiert und konfiguriert.

### 1. Installation und Funktionsweise
Fail2Ban überwacht die Logfiles des Systems auf verdächtige Anmeldeversuche. Nach einer definierten Anzahl an Fehlversuchen wird die IP-Adresse des Angreifers automatisch über die Firewall gesperrt.

**Installation:**
```bash
sudo apt update && sudo apt install fail2ban -y
```
<img width="1919" height="847" alt="Screenshot 2026-01-17 160917" src="https://github.com/user-attachments/assets/d636beb6-583b-4d22-ac42-c27428b26d11" />
*Abbildung 18: Status-Abfrage des Fail2Ban-Dienstes im Terminal, die den aktiven Schutz der SSH-Jail (sshd) bestätigt.*

## 🗄️ Datenbank-Setup & PHP-Anbindung

In diesem Abschnitt wurde die MariaDB-Datenbank konfiguriert und eine Test-Schnittstelle mit PHP geschaffen.

### 1. MariaDB Installation & Absicherung
Die Datenbank wurde mit `mariadb-secure-installation` gehärtet.
<img width="959" height="419" alt="Screenshot_MariaDB" src="https://github.com/user-attachments/assets/c0c0e6d4-e222-4b0a-8560-6362aa317624" />
*Abbildung 14: Erstmalige Anmeldung und Initialisierung der MariaDB-Konsole auf dem Webserver-01.*



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



<img width="1550" height="915" alt="Screenshot_ Datenbank_User_erstellen" src="https://github.com/user-attachments/assets/46d9895c-efd9-4916-94e5-376f9db67dbf" />
*Abbildung 15: SQL-Befehlskette zur Erstellung der Datenbank projekt_db sowie die Einrichtung des Datenbank-Benutzers webuser mit den entsprechenden Berechtigungen.*



### 3. PHP-Schnittstelle (db_test.php)

<img width="1919" height="826" alt="Screenshot 2026-01-17 160002" src="https://github.com/user-attachments/assets/b6f5015f-c5c5-43cb-82e0-a62c56161bd7" />
*Abbildung 16: Implementierung des PHP-Verbindungsskripts db_test.php im Texteditor Nano zur Verknüpfung von Webserver und Datenbank-Backend.*
<img width="1919" height="857" alt="Screenshot_Datenbank_Webseite" src="https://github.com/user-attachments/assets/9d759b69-361f-42cd-ac77-1ac965057f06" />
*Abbildung 17: Erfolgreicher Validierungstest im Webbrowser der Mint-Management-VM, der die aktive Kommunikation zwischen PHP und der MariaDB-Instanz bestätigt.*


# Dokumentation Phase 2: Aufbau des interaktiven Web-Services

## 1. System-Übersicht (LAMP-Stack)
Im Zeitraum von Tag 16 bis 22 wurde ein statischer Webserver in einen vollwertigen Application-Stack umgewandelt:
* **Linux:** Ubuntu Server (Webserver-01) in der DMZ (10.0.30.50).
* **Apache:** Webserver-Dienst mit SSL/TLS.
* **MariaDB:** Relationales Datenbanksystem.
* **PHP:** Backend-Logik.

> **Screenshot-Beleg: Die fertige Web-Oberfläche mit Einträgen**
> ![Web-Oberfläche](/img/website_Einträge.png)
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



