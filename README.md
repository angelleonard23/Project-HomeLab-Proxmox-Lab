# Enterprise Home Lab & Security Infrastructure

## 🎯 Projektziel
Transformation eines Standard-Heimnetzwerks in eine professionelle, segmentierte Lab-Umgebung. Ziel ist die Vertiefung von Kenntnissen in Virtualisierung, Firewalling (pfSense) und Containerisierung (Docker/Kubernetes).

# 🛡️ Project-HomeLab: Proxmox Infrastructure

## 💻 Hardware-Stack
- **Hypervisor:** AOOSTAR WTR PRO (AMD Ryzen 7 5825U, 64GB RAM)
- **Router:** TP-Link Archer AX18
- **ISP:** Magenta Fiber Box (aktuell im Double-NAT Modus / DMZ geplant)
- **Extender:** TP-Link RE330 (OneMesh für Arbeitszimmer-Konnektivität)

### 🖥️ System-Status (Woche 1)
![Dashboard](./Proxmox_Dashboard_CPU_RAM_Übersicht.png)
![Netzwerk](./grafik.png)

## 🌐 Netzwerk-Topologie
```text
[ Magenta Box ] <---> [ TP-Link Archer ] <--- LAN ---> [ AOOSTAR (Proxmox) ]
                            |
                         (WLAN)
                            |
                     [ TP-Link RE330 ] <--- WLAN ---> [ Arbeits-PC ]
