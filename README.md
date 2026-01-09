# Enterprise Home Lab & Security Infrastructure

## 🎯 Projektziel
Transformation eines Standard-Heimnetzwerks in eine professionelle, segmentierte Lab-Umgebung. Ziel ist die Vertiefung von Kenntnissen in Virtualisierung, Firewalling (pfSense) und Containerisierung (Docker/Kubernetes).

## 💻 Hardware-Stack
- **Hypervisor:** AOOSTAR WTR PRO (AMD Ryzen 7 5825U, 64GB RAM)
- **Router:** TP-Link Archer AX18
- **ISP:** Magenta Fiber Box (aktuell im Double-NAT Modus / DMZ geplant)
- **Extender:** TP-Link RE330 (OneMesh für Arbeitszimmer-Konnektivität)

## 🌐 Netzwerk-Topologie (Woche 1)
- **Management-Netz:** 192.168.1.0/24
- **Proxmox-Host:** 192.168.1.10
- **Gateway:** 192.168.1.1 (Archer)

## 📈 Fortschritt
- [x] Hardware-Setup & ISP-Stabilisierung
- [x] Hypervisor-Installation (Proxmox VE 8.x)
- [ ] pfSense Konfiguration & VLAN-Segmentierung (Woche 2)

```[ Magenta Box ] <---> [ TP-Link Archer ] <--- LAN ---> [ AOOSTAR (Proxmox) ]
                            |
                         (WLAN)
                            |
                     [ TP-Link RE330 ] <--- WLAN ---> [ Arbeits-PC ]```
