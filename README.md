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


### 🌐 Deployment des Web-Services (Abbildung 11)

Nach der Absicherung des Gateways wurde ein dedizierter Webserver auf Basis von **Debian 13 (Trixie)** implementiert. 

![Proxmox Management Übersicht](./img/pfsense_webserver_management.jpg)
*Abbildung 11: Zentrale Verwaltung in Proxmox. Die Übersicht zeigt die Koexistenz von Firewall, Management-VM und dem aktiven Apache-Webserver.*

#### Details zur Implementierung:
* **Infrastruktur:** Betrieb von drei spezialisierten VMs auf einem Proxmox-Node.
* **Service-Status:** Verifizierung des Apache2-Dienstes (`active/running`) direkt über die Proxmox-Konsole.
* **Effizienz-Faktor:** Durch die Nutzung der **Linux Mint 22.2 Xfce Edition** zur Administration bleibt die grafische Last minimal, was einen reibungslosen Parallelbetrieb aller Dienste ermöglicht.
