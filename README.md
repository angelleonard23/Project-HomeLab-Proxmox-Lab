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

### 2. Firewall-Regelwerk & DMZ-Isolierung
Das Regelwerk wurde so konfiguriert, dass eine "Einweg-Kommunikation" herrscht. Das Management-VLAN (10) hat vollen Zugriff auf den Webserver, während der Webserver keinen Zugriff auf das Management-VLAN hat.

**Wichtigste Regeln auf dem WEBSERVER-Interface:**
1. **BLOCK:** Source: `WEBSERVER subnets` -> Destination: `LAN subnets` (Verhindert Angriffe vom Webserver auf Management-Clients).
2. **PASS:** Source: `WEBSERVER subnets` -> Destination: `any` (Erlaubt Internetzugriff für Updates).


![Firewall_Rules](./img/Firewall_Rules_WEBSERVER_subnets_Destination_LAN_subnets.png)

### 3. Verifizierung der Konfiguration
Die erfolgreiche Einrichtung wurde durch folgende Tests bestätigt:
* **Connectivity:** Management-VM (10.0.10.50) kann Webserver (10.0.20.50) pingen.
* **Service:** Apache2 Default Page ist über den Browser im Management-Netz erreichbar.
* **Security:** Ping vom Webserver (10.0.20.50) zum Management (10.0.10.50) schlägt fehl (Request Timeout).

![Webserver_Isolierung_Verifikation](./img/DMZ_Isolierungstest_Fail.png)

---

