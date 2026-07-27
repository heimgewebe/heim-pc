---
id: runaway-guard
role: norm
status: canonical
last_reviewed: 2026-07-27
depends_on:
  - security
verifies_with:
  - tests/test_run_bounded_background.py
  - tests/test_install_docker_log_policy.py
---

# Minimaler Schutz gegen Runaway-Prozesse

## Ziel

Der Heim-PC begrenzt zwei häufige Schadenspfade mit vorhandenen Betriebssystemmechanismen:

1. bewusst als riskant eingestufte Hintergrundbefehle laufen in einer begrenzten transienten User-systemd-Unit;
2. neue Docker-Container erhalten standardmäßig größenbegrenzte rotierende Logs.

Diese Schicht ist kein allgemeiner Prozesswächter und versucht nicht, Endlosschleifen heuristisch zu erkennen.

## Bewusst ausgeschlossene Komplexität

Nicht Bestandteil dieses Vertrags sind:

* globale CPU-, Speicher- oder Dateigrößenlimits für die gesamte Benutzersitzung;
* ein permanenter Prozessscanner;
* automatische Prozessklassifikation oder ein CPU-Prozesskiller;
* `systemd-oomd`-Einführung;
* automatische Löschung gewachsener Dateien;
* automatische Neuerstellung bestehender Docker-Container.

Damit bleiben gewöhnliche Desktopprogramme, Builds, Backups und Echtzeit-Audiopfade unverändert.

## Begrenzter Hintergrundstart

Der kanonische Starter ist:

```text
python3 scripts/run_bounded_background.py --name <name> -- <programm> <argumente...>
```

Er verwendet ausschließlich argv und keine Shellauswertung. Die Standardgrenzen stehen in `config/runaway-guard.v1.json`:

* maximale Laufzeit: 2 Stunden;
* maximales RAM: 8 GiB;
* höchstens 256 Prozesse oder Threads in der Unit;
* maximale Größe einer einzelnen selbst geschriebenen regulären Datei: 1 GiB;
* reduzierte CPU- und IO-Gewichtung;
* Standardinput `/dev/null`;
* Ausgabe ausschließlich ins Journal;
* unit-spezifische Ausgaberatenbegrenzung;
* `KillMode=control-group`, damit beim Stoppen die gesamte Prozessgruppe endet.

Die Grenzen können pro bewusstem Start enger gesetzt werden. Unbegrenzte Nullwerte werden abgelehnt.

Interaktive Programme, die ein Terminal benötigen, gehören nicht in diesen Hintergrundpfad. Insbesondere ist `/dev/null` keine Reparatur für Programme, die EOF fehlerhaft als Aufforderung zur erneuten Ausgabe behandeln; die Ressourcen- und Journalgrenzen begrenzen in diesem Fall nur den Schaden.

## Docker-Loggrenze

`config/runaway-guard.v1.json` setzt für neue Container:

```json
{
  "log-driver": "local",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
```

`scripts/install_docker_log_policy.py` ergänzt diese Werte konfliktvermeidend in `/etc/docker/daemon.json` und bewahrt alle anderen Daemon-Einstellungen. Bereits vorhandene abweichende Logwerte blockieren die Installation statt still überschrieben zu werden. Vor einer Änderung wird die exakte Vorgängerversion hashgebunden gesichert.

Eine geänderte Daemon-Konfiguration erfordert einen Docker-Neustart. Bereits laufende Container behalten ihren bei der Erstellung gewählten Logging-Treiber und müssen nur im normalen Lebenszyklus neu erstellt werden; eine pauschale disruptive Neuerstellung ist ausdrücklich nicht Teil dieses Vertrags.

## Sicherheitsgrenze

Der Schutz gilt nur für:

* Befehle, die über den begrenzten Starter ausgeführt werden;
* Docker-Container, die nach Aktivierung der Daemon-Vorgabe neu erstellt werden;
* Grabowski-Aufgaben, soweit deren bestehende systemd-Kapsel eigene Laufzeit- und Speichergrenzen setzt.

Direkt in einer Shell gestartete Programme und beliebige Dateiumleitungen werden dadurch nicht global verändert. Diese begrenzte Reichweite ist beabsichtigt: Sie vermeidet einen zusätzlichen Host-Daemon und Fehlalarme bei legitimer Hochlast.
