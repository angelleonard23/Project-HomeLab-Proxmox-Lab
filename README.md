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

````
### 2. Warum Linux Mint Xfce in die Doku muss
In deinem Screenshot sieht man das saubere Desktop-Interface von Mint. Es ist wichtig zu erwähnen, **warum** du diese Version gewählt hast, um technisches Verständnis zu zeigen:
* Die **Xfce-Edition** ist ideal für Virtualisierungs-Labs, da sie extrem ressourcenschonend ist.
* Sie ermöglicht eine flüssige Bedienung des pfSense-Web-Interfaces, ohne den Proxmox-Host unnötig zu belasten.

---

### 3. Nächster Schritt: Screenshots einbinden
Da du jetzt tolle Screenshots hast (den Ping-Test und das Dashboard), binden wir diese unter den Text ein.

1.  Lade die Bilder in dein GitHub-Repository hoch (am besten in einen Ordner namens `images`).
2.  Füge diesen Code unter dein (hoffentlich jetzt funktionierendes) Diagramm ein:

```markdown
### 📊 Proof of Concept
Hier ist die erfolgreiche Verbindung der Management-VM durch die Firewall dokumentiert:

![pfSense Dashboard](./images/dein_bildname_dashboard.png)
*Abbildung 1: Zentrales Management-Dashboard in pfSense.*

![Ping Test](./images/dein_bildname_ping.png)
*Abbildung 2: Erfolgreicher ICMP-Ping auf 8.8.8.8 zur Verifizierung der Internet-Konnektivität.*
