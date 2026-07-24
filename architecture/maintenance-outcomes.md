---
id: maintenance-outcomes
role: norm
status: canonical
last_reviewed: 2026-07-24
depends_on:
  - storage-lifecycle
  - security
  - drift-policy
verifies_with:
  - config/maintenance-producers.v1.json
  - scripts/maintenance_outcomes.py
  - scripts/install_maintenance_outcomes.py
  - tests/test_maintenance_outcomes.py
---

# Wartungsergebnisse ohne zweite Wahrheitsinstanz

## Zweck

`maintenance_outcomes.py` verbindet vorhandene Wartungsproduzenten auf dem Heim-PC über ihre aktuellen Primärbelege. Der Collector führt keine Wartung aus. Er liest ausschließlich deklarierte systemd-Units, begrenzte Journalabschnitte, optionale Receiptdateien und exakte Bureau-Bindungen und schreibt ein einziges begrenztes Artefakt:

`~/.local/state/heim-pc/maintenance-outcomes/maintenance-outcomes.v1.json`

Das Artefakt ist eine abgeleitete Beobachtungsprojektion für Leitstand und Operator. Es ersetzt weder systemd, Grabowski, Bureau, Leitstand, Chronik noch die Lifecycle-Verträge der einzelnen Produzenten.

## Zuständigkeiten

| Quelle | Autorität |
|---|---|
| systemd-Service und Timer | aktueller Lauf-, Exit- und Aktivierungszustand |
| produzenteneigenes Receipt | inhaltlicher Erfolgsbeleg des jeweiligen Produzenten |
| Bureau | Kandidaten-, Aufgaben- und Prioritätswahrheit |
| Grabowski | Ausführung, Leases, Recovery und kontrollierte Effekte |
| Leitstand | Darstellung und Aufmerksamkeit |
| Maintenance-Outcomes | abgeleitete, read-only Ergebnisübersicht |

Ein fehlgeschlagener Service belegt keinen Root Cause. `systemd-service-result` bedeutet ausschließlich: systemd meldet einen terminalen Lauf mit `Result=success` und Exitstatus 0. Das belegt nicht automatisch die fachliche Richtigkeit seines Ergebnisses. Der Collector hält diese Grenzen im Artefakt fest; deklarierte, aber fehlende Evidence erzeugt gesonderte Review-Aufmerksamkeit.

## Produzentenvertrag

`config/maintenance-producers.v1.json` deklariert ausschließlich die überwachten Produzenten. Jeder Eintrag bindet:

- stabile Produzenten-ID;
- Service-Unit;
- optionale Timer-Unit;
- maximal zulässiges Alter des letzten belegten Erfolgs;
- explizite Erfolgsbasis `systemd-service-result`;
- zuständige Komponente;
- optionale, nur gehashte Evidence-Dateien aus explizit zugelassenen Zustands- und Leitstand-Artefaktwurzeln;
- optionale bestehende Bureau-Kandidaten- oder Taskbindung.

Nicht deklarierte Units werden nicht stillschweigend als Wartungsproduzenten behandelt. Die Policy ist Bestandteil des commitgebundenen Releases.

## Zustände

Der Collector projiziert genau folgende Ergebniszustände:

- `observed`: laufender oder innerhalb des SLO erfolgreich abgeschlossener Produzent;
- `stale`: letzter belegter Erfolg ist älter als die deklarierte Grenze;
- `failed`: der aktuelle systemd-Lauf endete fehlgeschlagen;
- `unknown`: Unit, Laufzeit oder Erfolgsbeleg ist nicht ausreichend beobachtbar;
- `not-applicable`: für künftige explizit nicht anwendbare Produzenten reserviert.

`failed` und `stale` erzeugen nur abgeleitete Aufmerksamkeit. Eine deklarierte, aber nicht geladene oder nicht aktive Timer-Unit erzeugt unabhängig vom Alter des letzten Erfolgs `timer-not-active`-Aufmerksamkeit. Sie erteilen keine Reparatur-, Retry-, Restart-, Cleanup- oder Taskbefugnis.

## Fehlerdeduplizierung

Fehlerfingerprints binden:

- Produzenten-ID und Unit;
- systemd-Ergebnis und Exitstatus;
- höchstens vier begrenzte, redigierte und normalisierte Fehlermeldungen.

Dynamische Zeitstempel, lange Zahlen, Hex-Identitäten und Home-Pfadpräfixe werden normalisiert. Derselbe fehlgeschlagene systemd-Invocation erhöht den Zähler nicht bei jedem Collector-Lauf erneut. Erst eine neue fehlgeschlagene Invocation mit demselben Fingerprint erhöht `consecutive_failures`.

Der stabile `escalation_key` kann von Leitstand oder einem späteren expliziten Operatorpfad zur Deduplizierung verwendet werden. Der Collector selbst schreibt keine Bureau-Kandidaten. Das Vorgängerartefakt wird vor Wiederverwendung von Erfolgs- oder Fehlerzählern über seinen kanonischen `artifact_sha256` geprüft; Identitäts-, Struktur- oder Digestabweichungen blockieren den Folgelauf statt Zähler still zurückzusetzen.

## Bureau-Grenze

Vorhandene Kandidaten werden ausschließlich über `bureau operator-candidate-assess --candidate-id ...` gelesen. Eine Taskbindung kann demselben exakten Assessment hinzugefügt werden. Breite Live-Register-Listen sind keine Kandidatenwahrheit und werden nicht zur Supersession verwendet.

Die Reparatur des Systemkatalog-Watchdogs folgt derselben Regel: exakte Kandidatenbewertung, unmittelbare Revalidierung vor `live-register`, danach entweder Deduplizierung oder an die gerade gelesene Event-ID gebundene Supersession. Eine konkurrierende Änderung blockiert oder wird erneut read-only bewertet; sie wird nicht überschrieben.

## Datenschutz und Begrenzung

Journalzugriffe erfolgen nur für fehlgeschlagene Läufe, sind auf deren Start-/Endzeitfenster, Fehlersignale und 200 Einträge je Unit begrenzt. Ausgegeben werden höchstens vier Fehlermeldungen mit jeweils höchstens 600 Bytes; strukturierte `error`-, `message`- und `reason`-Felder haben Vorrang vor generischen systemd-Zeilen. ANSI-Sequenzen und Home-Präfixe werden redigiert. Evidence-Dateien werden ausschließlich unter den zugelassenen `$HOME/.local/state/{heim-pc,grabowski,leitstand,repoground}`-Wurzeln oder `$HOME/repos/leitstand/artifacts` und nur als eigentümerkontrollierte, reguläre Nicht-Symlink-Dateien bis vier MiB gelesen; im Artefakt erscheinen nur Pfadprojektion, Größe, `mtime` und SHA-256.

Private Inhalte, Secretdateien, Browserprofile, Keyrings und breite Home-Scans sind außerhalb des Vertrags.

## Installation und Rollback

`install_maintenance_outcomes.py` installiert aus einem sauberen exakten Git-Commit:

- Script und Policy unter einem commitbenannten Releaseverzeichnis;
- gerenderte systemd-Service- und Timer-Units;
- ein Installationsreceipt mit Digests und Readback.

Der Timer läuft alle 15 Minuten mit zufälliger Verzögerung. Rollback bedeutet, die vorherige Unitversion wiederherzustellen oder den neuen Timer zu deaktivieren und nur die abgeleitete Artefaktprojektion zu entfernen. Produzentenzustände, Bureau-Historie und Receipts werden nicht verändert.
