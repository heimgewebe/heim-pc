# NixOS – Produktivintegration, Agenten und Konsolidierung

Status: **Arbeitsplan; einzelne Phasen erst nach Live-Abnahme abhaken**
Zielpfad: `heimgewebe/heim-pc/nixos/implementation-plan-2026-10-25.md`
Stand der Beobachtungen: 2026-10-25, Europe/Berlin

## Ziel und Arbeitsregeln

NixOS auf der Seagate dauerhaft zuverlässig betreiben und über ChatGPT/Grabowski administrieren. Das separate Pop!_OS auf der WD_BLACK SN850X erhalten. Funktionalität, geringe Betriebsreibung und echte Wiederherstellbarkeit haben Vorrang vor redundanter Infrastruktur und Formalismus. Bestehende Dienste, NixOS-Module und Grabowski-Funktionen wiederverwenden.

- **Writer:** Grabowski allein für autorisierte Repository-, Host- und Runtime-Änderungen. Großer Adler bleibt unabhängiger Read-only-Prüfer; Gegner führt frühe Gegenproben durch, ist aber kein Reviewer und keine Evidenzquelle; Nixer bleibt Nix-Spezialist. Bureau ist Task-/Claim-Authority und kein zweiter Writer.
- **Evidenz:** Vor Änderungen Git-Head, Branch, Diff, Dirty-State, CI, aktive Tasks/Leases sowie Dienstzustand frisch prüfen. Nach der Änderung dieselbe **tatsächlich installierte** Revision prüfen. Nicht allein aus dem Plan auf Fertigstellung schließen.
- **Risiko:** Keine WD-/ESP-/Firmware- oder destruktiven Datenträgeränderungen. Backup und Restore mit echten Testdaten nachweisen, niemals Erfolgsmarker fingieren. Geschützte NixOS-Rückfallgeneration erhalten.
- **Prüftiefe:** Gezielte Checks zuerst, vollständige `nix flake check` nur bei entsprechendem Änderungsumfang/Risiko; Build/Boot-/Restore-Nachweise bei wirksamen Systemänderungen.

## Live-Befunde vom 25.10.2026 (keine dauerhaften Wahrheitsbehauptungen)

- NixOS 26.05 läuft auf `heim-pc`; `grabowski-operator.service` und SSH wurden als aktiv beobachtet.
- Grabowski-Laufzeit aus HEAD `6a6360a92be11d24d85e9b002bb34ac2b07672d5` aktiv; 203 Werkzeuge registriert. PR `heimgewebe/grabowski#1636` blieb offen.
- `restic-backups-heim-pc.timer` läuft als **System-Timer**. Restic-Snapshots erfolgreich, unter anderem `c0c3152f`; frühere Restore- und Repo-Prüfung laut Recovery-Evidenz positiv. Neue Grabowski-Recovery-Prüfung erkennt den Timer, meldet aber `local_backup_fresh=false` und verlangt einen echten frischen lokalen Backup-/Restore-Sentinel.
- `nixer-headless.service` zuletzt `failed/start-limit-hit`, verursacht durch OOM während einer umfangreichen Flake-Prüfung. `MemoryMax=4294967296` (4 GiB) bei physisch ca. 64 GiB RAM. Die genaue ressourcensparende Korrektur ist noch festzulegen und zu testen.
- `heimgewebe/heim-pc#240`: offen/Draft, HEAD `9311c986592463e58da1d453d922716cc80612ac` bei letzter Prüfung.
- Grabowskis Schreibtransport war nach dem Releasewechsel zunächst wegen `transport assertion runtime binding mismatch` blockiert; bei neuer Prüfung meldete `grabowski_status` wieder `mutation_gate_open=true`. **Vor jeder Mutation aktuell prüfen und nur den vorhandenen signierten Writer verwenden.**

## Ausführung und Akzeptanz

### P0.1 – Recovery vollständig konvergieren

- [x] Den tatsächlich vorhandenen Restic-System-Timer feststellen und auf Grabowski-Seite erkennen lassen (bereits in der installierten neuen Grabowski-Revision sichtbar).
- [ ] Vorhandenen Backup- und Restore-Vertrag samt Sentinel-Erzeugung ansehen; keinen zweiten konkurrierenden Timer/Backup-Pfad einführen.
- [ ] Einen frischen nativen Restic-Lauf samt echter Wiederherstellung und Repository-Integritätsprüfung durchführen; kanonischen Erfolgsbeleg durch den dafür vorgesehenen Ablauf erzeugen.
- [ ] `grabowski_recovery_status` unmittelbar erneut auswerten: `local_backup_fresh=true`, Timer aktiv und korrekte Ausführbarkeit nachgewiesen.
- [ ] Rootbroker- und nichtdestruktiven privilegierten Funktionsweg auf installierter Revision abnehmen.

**Abnahme:** Keine veralteten Recovery-Vorbedingungen, echte Rücksicherung nachgewiesen, benötigte administrative Aktionen funktionieren.

### P0.2 – Nixer stabilisieren

- [ ] Nixer-Logs und aktuelle systemd-Properties nach eventuell parallelen Änderungen frisch erfassen; OOM-Diagnose reproduzierbar gegen gemessenen Spitzenbedarf bestätigen.
- [ ] Die 4-GiB-Speichergrenze im zuständigen deklarativen NixOS-Modul bedarfsgerecht anpassen oder unnötige simultane Flake-Auswertungen begrenzen; zuerst die kleinere wirksame Änderung wählen.
- [ ] Gezielte Nix-Auswertungen sowie eine repräsentative größere Flake-Prüfung ausführen, ohne Neustartschleife oder Memory-Kill.
- [ ] Nach erfolgreicher Ursachenbehebung Startlimit zurücksetzen, Dienst kontrolliert aktivieren und Nixer-MCP-Funktion prüfen.

**Abnahme:** Nixer ist stabil erreichbar und führt alltägliche sowie belastende Nix-Abfragen ohne OOM-Abbruch durch.

### P0.3 – GitHub- und Installationsstände zusammenführen

- [ ] Branches, HEADs, offene Reviews und CI für `heim-pc#240` und `grabowski#1636` **frisch** lesen. Unbekannte parallele Änderungen nicht überschreiben.
- [ ] Noch offene Quellstandkonflikte und konkrete CI-/Review-Fehler gezielt korrigieren.
- [ ] Geprüfte Änderungen über Grabowski veröffentlichen und gemäß Repo-Verträgen integrieren.
- [ ] Die installierte Laufzeit auf denselben geprüften Quellstand bringen und tatsächliche Funktionen nach Installation erneut prüfen.

**Abnahme:** PRs konsistent abgeschlossen; produktiv laufende Revision belegt, nicht bloß Merge oder CI-Grün.

### P1.1 – Agenten ohne Doppelinstallation integrieren

- [ ] Bestand/Erreichbarkeit vorhandener Connectoren und Dienste für Großer Adler, Gegner, Nixer und Bureau prüfen.
- [ ] Gegner an wesentlichen frühen Entscheidungen als kurze Gegenprobe einsetzen.
- [ ] Großen Adler unabhängig auf aktueller Revision lesend verifizieren lassen.
- [ ] Bestehende Bureau-Pickup/Claim/Closeout-Funktion in Grabowski mit kleiner reversibler Aufgabe Ende-zu-Ende testen.
- [ ] Nur belegte fehlende Teile als deklarative Dienste ergänzen.

**Abnahme:** Ein kleiner echter Arbeitsauftrag läuft über eindeutige Zuständigkeiten, Grabowski-Änderung, unabhängige Verifikation und Bureau-Ergebnisbeleg.

### P1.2 – Ordnung und Struktur

- [ ] Bestehende `nixos/`-Module, `architecture/`, `manifest/repo-index.yaml` und `AGENTS.md` als Struktur beibehalten; keine kosmetische Großmigration.
- [ ] Bestätigt veraltete Boot-Provisorien, doppelte Timer, obsolete Units und historische fehlgeschlagene Grabowski-Jobs von laufenden Fehlern trennen.
- [ ] Nur nach belegtem Nutzen bereinigen; Autostarts, Nix-Generationen und Datenerhalt danach prüfen.
- [ ] Minimal dokumentieren: Operator-Einstieg, Backup/Restore, Update, Rollback, unabhängiger Pop!_OS-Fallback.

**Abnahme:** Keine belegten unnötigen Doppelzuständigkeiten; Betrieb und Wiederherstellung aus vorhandenen Repo-Quellen nachvollziehbar.

### P2 – Gesamtabnahme

- [ ] NixOS dauerhaft von der Seagate im normalen Bootpfad bestätigt; geschützte NixOS-Generation vorhanden.
- [ ] Pop!_OS unabhängig bootfähig, ohne Mutationen seiner WD-/ESP-Daten.
- [ ] Grabowski-203, Rootbroker, SSH, Nixer, Agentenrollen und Bureau End-to-End nachgewiesen.
- [ ] Automatisches Backup, wirkliche Restore-Probe und erneuter Recovery-Gate-Lesetest bestanden.
- [ ] Installierte Revision, GitHub-/CI-Evidenz und tatsächlich getestete Version stimmen überein.

## Reihenfolge nach der Planablage

1. Frische Recovery- und Nixer-Evidenz sichern; Restic-System-Timer und vorhandene Wiederherstellungsroute wiederverwenden.
2. Die jeweils kleinste Korrektur umsetzen und vor dem nächsten Eingriff erneut testen.
3. Auf laufende parallel geschützte NixOS-/XRDP-Branches Rücksicht nehmen und keine fremden Leases übergehen.
4. Offene PRs nur mit aktuellen Reviews, CI und exakt verifizierter Runtime als integriert markieren.
5. Erst anschließend Agentenrollen und Systemhygiene abschließen.

Dieser Text ist ein Arbeitsplan, keine Live-Primärquelle oder erbrachte Abnahme. Statusfelder bei nächster Bearbeitung gegen die zuständigen Dienste aktualisieren.