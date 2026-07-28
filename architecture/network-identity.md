---
id: network-identity
role: norm
status: canonical
last_reviewed: 2026-07-28
depends_on:
  - security
  - runaway-guard
verifies_with:
  - tests/test_install_network_identity.py
  - tests/test_network_link_diagnostics.py
---

# Netzwerkidentität und Ethernet-Linkdiagnose

## Zweck

Der Heim-PC muss seinen eigenen statischen Hostnamen lokal auflösen, bevor DNS befragt wird. Andernfalls können viele kurzlebige lokale Prozesse denselben Namen über die DHCP-Suchdomäne an Pi-hole senden und dessen clientbezogenes Rate-Limit auslösen. Ein solcher Fehler wirkt für Anwendungen wie ein Internetausfall, obwohl Routing und die physische Verbindung weiterhin funktionieren.

Separat wird die ausgehandelte Ethernet-Geschwindigkeit read-only geprüft. Diagnose und Mutation bleiben getrennt: Eine langsame Aushandlung darf nicht durch einen unbelegten Remote-Link-Flap oder erzwungene Geschwindigkeit kaschiert werden.

## Vertrag

`config/network-identity.v1.json` bindet:

* den erwarteten statischen Hostnamen `heim-pc`,
* die lokale Loopback-Zuordnung `127.0.1.1`,
* die erwartete Default-Route-Schnittstelle `enp6s0`,
* die minimale erwartete Ethernet-Geschwindigkeit von 1.000 Mbit/s.

Der Hostname-Eintrag wird als klar markierter Block in `/etc/hosts` ergänzt. Unabhängige Einträge bleiben byteinhaltlich erhalten. Vor jeder Änderung wird der exakte Vorzustand hashgebunden gesichert. Symlinks, nicht reguläre Ziele, konkurrierende Vorzustandsänderungen, widersprüchliche unverwaltete Hostname-Einträge und beschädigte Marker blockieren fail-closed.

## Installation

```bash
python3 scripts/install_network_identity.py
python3 scripts/install_network_identity.py --apply --expected-head <commit>
```

Ohne `--apply` entsteht nur ein Plan. Die produktive Installation erfordert Root-Rechte und einen sauberen, exakt commitgebundenen Checkout. Backups liegen unter `/var/lib/heim-pc/network-identity/hosts-backups/`. `/var/lib` ist der explizite, bereits durable Backup-Anchor. Vor dem Öffnen einer Backup-Datei validiert der Installer jede darunterliegende Verzeichniskomponente fail-closed auf Pfadtyp, Symlinkfreiheit, Root-Eigentum und nicht gruppen-/weltbeschreibbaren Modus. Anschließend synchronisiert er bei jeder Installation die vollständige Verzeichnisahnenkette vom Anchor bis zum direkten Elternverzeichnis des Backup-Roots, auch wenn eine unterbrochene frühere Ausführung die Komponenten bereits angelegt hatte. Erst nach dem Datei-`fsync` und dem `fsync` des Backup-Roots darf `/etc/hosts` atomar ersetzt werden. Ein abweichender `--backup-root` erfordert einen passenden expliziten `--backup-anchor`; der Dateisystem-Root ist als Anchor gesperrt.

Nach der Installation muss die lokale Resolverkette `heim-pc` über `127.0.1.1` beantworten. Die eigentliche Abnahme misst zusätzlich einen lokalen Git-Clone unter Systemaufrufbeobachtung: Er darf für den eigenen Hostnamen keine DNS-Verbindung mehr öffnen. Erst ein Lastlauf unterhalb des Pi-hole-Grenzwerts belegt, dass der ursprüngliche Ausfallpfad geschlossen ist.

## Linkdiagnose

```bash
python3 scripts/network_link_diagnostics.py
python3 scripts/network_link_diagnostics.py --strict
```

Die Diagnose ermittelt die aktive IPv4-Default-Route aus `/proc/net/route`, liest feste Sysfs-Felder und wertet `ethtool` aus. Sie verändert weder NetworkManager noch Autonegotiation noch den Link.

Ist Autonegotiation aktiv, der Adapter bietet mindestens 1 Gbit/s an und der Link steht dennoch nur mit 100 Mbit/s, liegt der wahrscheinlichste Fehlerbereich außerhalb der lokalen Softwarekonfiguration:

1. Kabel oder Steckkontakt nutzt nicht alle vier Adernpaare,
2. Router- oder Switch-Port ist auf 100 Mbit/s begrenzt oder fehlerhaft,
3. der Gegenport handelt aufgrund physischer Signalqualität herunter.

Die Diagnose belegt nicht, welches konkrete Kabelpaar oder welcher Gegenport defekt ist. Dafür wäre ein kontrollierter Kabeltest oder physischer Gegentest nötig, der die aktive Netzwerkverbindung unterbrechen kann.

## Grenzen

* Die Loopback-Zuordnung gilt nur auf dem Heim-PC. Andere Geräte lösen `heim-pc` weiterhin über Heimberry/Fritzbox auf.
* Die Änderung hebt Pi-holes Rate-Limit nicht an und umgeht Heimberry nicht durch einen zweiten öffentlichen DNS-Server.
* Die Änderung verhindert keine DNS-Stürme für andere Namen.
* Ein grüner Linkdiagnose-Lauf belegt keine Ende-zu-Ende-Internetleistung.
