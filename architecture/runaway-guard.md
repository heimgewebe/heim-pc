---
id: runaway-guard
role: norm
status: canonical
last_reviewed: 2026-09-25
depends_on:
  - security
verifies_with:
  - tests/test_run_bounded_background.py
  - tests/test_install_docker_log_policy.py
  - tests/test_memory_pressure_guard.py
  - tests/test_install_memory_pressure_guard.py
---

# Schutz gegen Runaway-Prozesse und globalen Speicherkollaps

## Ziel

Der Heim-PC begrenzt vier getrennte Schadenspfade:

1. bewusst als riskant eingestufte Hintergrundbefehle laufen in einer begrenzten
   transienten User-systemd-Unit;
2. neue Docker-Container erhalten standardmäßig größenbegrenzte rotierende Logs;
3. ein unabhängiger systemweiter Grabowski-Memory-Guard beendet einen belegten
   Grabowski-Speicherrunaway kontrolliert, bevor er den ganzen Host in einen
   globalen OOM zieht;
4. eine passive, begrenzte Telemetrie hält Prozess-, Cgroup-, PSI-, RAM- und
   Swap-Evidenz für spätere Attribution fest.

Auslöser für die Erweiterung ist der belegte globale OOM vom 25.09.2026. Der
Grabowski-Hauptprozess erreichte unmittelbar vor dem Kollaps ungefähr 47 GiB RSS
und zusätzlich rund 13 GiB Swap. Gleichzeitig fiel MemAvailable auf 0 MiB und
der Swap war praktisch vollständig belegt. Kleine Kubernetes-Prozesse wurden
zuerst vom Kernel-OOM-Killer entfernt, ohne den Speicherdruck zu lösen.

Die vorherige Annahme, nur bewusst gekapselte Hintergrundjobs müssten begrenzt
werden, ist damit widerlegt.

## Bewusst ausgeschlossene Komplexität

Nicht Bestandteil dieses Vertrags sind:

* ein harter globaler MemoryMax für die gesamte Benutzersitzung;
* MemoryHigh=18G, MemoryMax=24G oder MemorySwapMax=4G auf
  grabowski-operator.service;
* automatischer Rechner-Reboot;
* regelmäßiges kill -9 einzelner Python-PIDs;
* earlyoom oder systemd-oomd als konkurrierende hostweite Opferwahl;
* automatische CPU- oder Endlosschleifenklassifikation;
* automatische Löschung gewachsener Dateien;
* automatische Neuerstellung bestehender Docker-Container;
* die Behauptung, die Guard-Reaktion behebe bereits die interne
  Grabowski-Leak-Ursache.

Damit bleiben gewöhnliche Desktopprogramme, Audio, Remotezugriff, Builds und
Backups ohne pauschales Session-Limit.

## Begrenzter Hintergrundstart

Der kanonische Starter ist:

    python3 scripts/run_bounded_background.py --name <name> -- <programm> <argumente...>

Er verwendet ausschließlich argv und keine Shellauswertung. Die Standardgrenzen
stehen in config/runaway-guard.v1.json:

* maximale Laufzeit: 2 Stunden;
* maximales RAM: 8 GiB;
* höchstens 256 Prozesse oder Threads in der Unit;
* maximale Größe einer einzelnen selbst geschriebenen regulären Datei: 1 GiB;
* reduzierte CPU- und IO-Gewichtung;
* Standardinput /dev/null;
* Ausgabe ausschließlich ins Journal;
* unit-spezifische Ausgaberatenbegrenzung;
* KillMode=control-group, damit beim Stoppen die gesamte Prozessgruppe endet.

Die Grenzen können pro bewusstem Start enger gesetzt werden. Unbegrenzte
Nullwerte werden abgelehnt.

Interaktive Programme, die ein Terminal benötigen, gehören nicht in diesen
Hintergrundpfad.

## Unabhängiger Grabowski-Memory-Guard

heim-pc-grabowski-memory-guard.service ist ein eigener root-systemd-Dienst in
system.slice. Er ist weder Kindprozess noch PartOf von
grabowski-operator.service.

Damit bleibt die Rettungsinstanz funktionsfähig, wenn der Operator selbst
Speicher verliert oder nicht mehr antwortet.

Die Policy steht in config/memory-pressure-guard.v1.json. Alle 15 Sekunden
werden ausschließlich folgende Entscheidungsdaten frisch gelesen:

* MainPID, ActiveState und ControlGroup von grabowski-operator.service;
* RssAnon, VmRSS und VmSwap des exakten MainPID;
* MemAvailable des Hosts;
* memory.current und memory.swap.current der Operator-Cgroup.

Vor jeder Bewertung muss sowohl systemd als auch /proc/<pid>/cgroup exakt
/system.slice/grabowski-operator.service bestätigen. Zusätzlich liest der Guard
die Procfs-Startzeit und die Cgroup vor und nach dem Status-Snapshot erneut und
liest anschließend MainPID/ControlGroup noch einmal aus systemd. Ein regulär
verschwundener oder inzwischen ersetzter MainPID wird als veraltete Stichprobe
verworfen; PID-Reuse oder eine inkonsistente Prozessidentität führt fail-closed
zu keiner Mutation. Auch der persistente Bestätigungszähler für zwei
aufeinanderfolgende 24-GiB-Samples ist an PID **und** Procfs-Startzeit gebunden.
Ein gleicher numerischer PID mit neuer Startzeit beginnt deshalb wieder bei
Sample 1. Älterer Schema-v1-State ohne persistierte Startzeit wird mit Startzeit
0 eingelesen und erzwingt damit ebenfalls eine frische Bestätigungssequenz.

### Startschwellen

Die konservative Anfangspolicy lautet:

* ab 18 GiB RssAnon: Warnereignis, keine Mutation;
* ab 24 GiB RssAnon in zwei aufeinanderfolgenden Stichproben:
  kontrollierter systemctl restart grabowski-operator.service;
* bei höchstens 8 GiB MemAvailable und mindestens 12 GiB Grabowski-RssAnon:
  sofortiger kontrollierter Restart;
* bei demselben Hostdruck alternativ ab 24 GiB `anon_pressure = RssAnon + VmSwap`:
  sofortiger Restart auch nach starker Auslagerung. Die eigene Policygröße
  heißt `emergency_anon_pressure_bytes`; Warnung und Zwei-Sample-Regel bleiben
  ausschließlich an residentem RssAnon gebunden.

Die zusätzliche Swap-Notfallschwelle wurde separat plausibilisiert: 240 passive
Snapshots vom 25.09.2026, etwa 10:00–12:06 UTC, hatten höchstens
18.709.430.272 Byte (17,43 GiB) Hauptprozess-RSS plus Swap. RSS enthält auch
nicht-anonyme Seiten und ist damit eine konservative Obergrenze. 24 GiB lassen
rund 38 Prozent Abstand zu diesem beobachteten Maximum. Die Samples hatten
mindestens 29,47 GiB MemAvailable; sie beweisen keine vollständige Kalibrierung
aller künftigen Lasten oder aller Drucksituationen. Der Regressionstest für
11 GiB RssAnon plus 22 GiB Swap bei 512 MiB MemAvailable wählt jetzt Restart;
derselbe Footprint bei gesundem Hostdruck löst den neuen Pfad nicht aus.

Die Attribution verwendet den Hauptprozess und nicht allein MemoryCurrent der Cgroup. MemoryCurrent enthält auch reclaimbaren
Dateicache, Slab und andere Cgroup-Anteile; der aktuelle gesunde Betrieb hat
bereits gezeigt, dass dadurch ein niedriger Hardcap zu früh auslösen könnte.

### Restart- und Circuit-Breaker-Regeln

Ein erfolgreicher Restart muss anschließend durch alle folgenden Readbacks
bestätigt werden:

* Unit wieder active;
* neuer MainPID größer 0;
* neuer PID unterscheidet sich vom vorherigen;
* ControlGroup weiterhin exakt die erwartete Operator-Cgroup.

Es gilt ein Restart-Cooldown von 10 Minuten und maximal drei Restarts in einer
Stunde. Tritt während des Cooldowns erneut die Host-Notfallschwelle ein oder ist
das Stundenbudget ausgeschöpft, öffnet der Guard den Circuit Breaker und stoppt
den Operator kontrolliert.

Vor einem Restart wird zuerst die beim Memory-Sample gebundene Prozessidentität
frisch gegen Unit-MainPID, ControlGroup, `/proc/<pid>/stat`-Startzeit und
Prozess-Cgroup geprüft. Eine stale oder unlesbare Precondition (auch ein
`systemctl show`-Timeout) führt zu einem auditierbaren Abort ohne Restart,
Budgetverbrauch oder künstliches Öffnen des Circuits. Der nächste Tick misst neu.

Erst nach bestandener Restart-Precondition und vor jedem `restart` beziehungsweise
`stop-circuit` schreibt der Guard die beabsichtigte Aktion, das Restart-Budget und
`circuit_open=true` atomar und `fsync`-gebunden als `pending_action`.
Schlägt diese Persistenz fehl, wird der Operator nicht mutiert. Nach dem Intent-
`fsync` wird dieselbe Restart-Identität unmittelbar vor `systemctl` erneut geprüft,
weil das Target während der Storage-I/O gewechselt haben kann. Ein stale oder
unlesbarer zweiter Check nimmt den vorläufigen Intent samt Budgeteintrag dauerhaft
zurück und protokolliert den Abort. Schlägt diese Rücknahme fehl, bleibt der
persistierte Intent fail-closed erhalten. Eine atomare Compare-and-Restart-Operation
bietet systemd nicht; zwischen letzter Prüfung und Dispatch bleibt ein kleines
unvermeidbares Race-Fenster, ohne eine dazwischenliegende State-I/O-Phase.
Stirbt der Guard
nach dem Intent-Write oder bleibt ein versuchter Eingriff unklar, bleibt der
Circuit offen; Recovery versucht niemals blind einen zweiten Restart.

SIGTERM/SIGINT werden während der begrenzten Transaktion bis einschließlich
finalem State und Audit zurückgestellt und anschließend mit dem ursprünglichen
Handler erneut zugestellt. Kindprozesse behalten ihre normalen Signalmasken.
Die Unit setzt `KillMode=mixed`: systemd sendet das anfängliche Stop-Signal nur
an den Guard-Hauptprozess, damit ein bereits wartender `systemctl`-Client seine
Antwort liefern kann. Das abschließende SIGKILL bleibt mit `SendSIGKILL=yes`
gruppenweit aktiv; es entstehen keine vom Service-Lifecycle abgekoppelten Kinder.
Der Regressionstest verwendet einen echten Command-Kindprozess in einer
isolierten Prozessgruppe und reproduziert auch den fehlerhaften früheren
`control-group`-Signalweg. Der normale Abschluss wartet auf das Kind und reapet es.
`TimeoutStopSec=150s` deckt die maximal konfigurierbaren systemctl-/Wartephasen
ab. SIGKILL, Stromverlust oder dauerhaft blockierte Storage-I/O bleiben
Crashfälle und konvergieren über den persistenten fail-closed Intent.

Recovery verwendet dieselbe Aktionsabwicklung:

| Persistenter Zustand | Frischer Target-Zustand | Ergebnis |
| --- | --- | --- |
| Pending Stop oder Restart, Circuit offen | inactive/failed und PID 0 | Pending auditierbar löschen; Circuit offen lassen; kein neuer Eingriff |
| Circuit offen, mit oder ohne Pending | active/activating/reloading oder anderer noch nicht abgeschlossener Zustand | Stop-Intent persistieren, stoppen, Inaktivität verifizieren |
| Circuit offen, ohne Pending | inactive/failed und PID 0 | Keine weitere Stop-Mutation |
| Restart-Precondition stale/unlesbar | Noch kein Mutationsversuch | Abort, frische Confirmation erforderlich, Budget unverändert |

Ein Zombie-/Dead-Prozess in procfs gilt als verschwundene Observation, auch
wenn systemd kurzzeitig noch denselben alten MainPID meldet.

Ein erfolgreicher, eindeutig verifizierter Restart finalisiert den State erst
danach auf den neuen PID, ersetzt den vorläufigen Restart-Zeitstempel durch den
tatsächlichen Abschlusszeitpunkt und löscht `pending_action`. Persistierte
Zeitpunkte sind mindestens so groß wie der vorherige History-Eintrag und die
Observation; ein Wall-Clock-Rücksprung erzeugt keine unsortierte Historie. Ein nonzero
`systemctl`-Returncode kann auch bei zufällig neuem PID niemals als erfolgreicher
Guard-Restart gelten.

Alle State-Mutationen des Daemons und `--reset-circuit` sind über denselben
exklusiven Directory-`flock` serialisiert; Preflight und reine State-Validierung
verwenden denselben Lock read-only. Der StateDirectory-Pfad wird komponentenweise
mit `O_NOFOLLOW` geöffnet; nach erfolgreicher Verifikation bleiben Lock,
State-Reads, atomare State-Replaces sowie Event-Appends an genau diesem
Directory-FD gebunden. Der StateDirectory muss dem effektiven UID gehören
(root im Livebetrieb) und exakt Mode 0700 haben; `state.json` muss nach
`fstat` regular, gleich-owned, einmal verlinkt und Mode 0600 sein. Diese
Trust-Prüfungen gelten ebenso für reine Validation und Preflight.
Ein späterer Rename oder Austausch eines sichtbaren
Pfadbestandteils kann den laufenden Tick damit nicht auf einen anderen State
umlenken. Zugleich kann ein überlappender Guard-Tick einen manuellen Circuit-Reset
nicht mit einem veralteten State zurücküberschreiben.

`systemctl show` ist auf 10 Sekunden, `restart` auf 45 Sekunden und `stop`
auf 25 Sekunden begrenzt. Timeout wird als `GuardError` behandelt und lässt
einen bereits vorbereiteten Circuit fail-closed offen. Fehlgeschlagene oder
unklare Eingriffe werden vor dem Weiterreichen des Fehlers in `latest.json`
und `events.jsonl` versucht zu protokollieren; beide Writes werden auch bei
Ausfall einer Auditfläche versucht. Bei unbeschreibbarem Storage kann kein
dauerhafter Auditbeleg garantiert werden. Der Rechner wird niemals
automatisch rebootet. Ein offener Circuit bleibt absichtlich fail-closed, bis er
nach Ursachenprüfung manuell zurückgesetzt wird.

`--reset-circuit` verlangt nachgewiesene Inaktivität (inactive/failed und PID 0).
Nur nach erfolgreicher FD-Trust-Prüfung darf ungültiges JSON beziehungsweise
Schema-/Wertekorruption in `state.corrupt.<timestamp>.json` im selben Directory
bewahrt und durch Default-State ersetzt werden; das Reset-Event benennt das
Archiv. Symlink-, Owner-, Mode-, I/O- oder Größenverletzungen werden nicht
als reparierbare Wertefehler behandelt. Archive sind explizite Recovery-Belege,
kein automatisch wachsender Normalbetriebspfad.

### Unabhängigkeit des Guards

Der Guard selbst erhält:

* eigenes systemd-Service-Cgroup;
* MemoryMax=128M;
* MemorySwapMax=0, damit die Rettungsinstanz unter Swap-Thrashing nicht selbst
  erst eingelagert werden muss;
* OOMScoreAdjust=-900;
* einen root-eigenen State-Pfad unter
  /var/lib/heim-pc/grabowski-memory-guard;
* keinen Schreibzugriff auf die Grabowski-State-Verzeichnisse.

Damit hängt die Rettungslogik weder vom Grabowski-Prozess noch von dessen Audit-
oder Receipt-Locks ab. Gesunde Ticks schreiben `state.json` nur bei einer
tatsächlichen State-Änderung; im Loop bleiben reine `action=none`-Ticks auf
stdout still. Atomare State-/Installations-Replaces werden zusätzlich durch
Directory-`fsync` dauerhaft gemacht. Tailscale und SSH bleiben zusätzliche
manuelle Rettungswege außerhalb der Operator-Cgroup.

`latest.json` bleibt pro Tick fsync-gebunden, damit der Deployment-Health-Gate
echte frische Evidenz hat. Unbelegte I/O-Scheduler-Optimierungen werden hier nicht
eingeführt. Rohe Storage-`OSError` beenden den Prozess mit Fehler; systemd darf
ihn mit `Restart=on-failure` neu starten. Persistierte Intents verhindern dabei
einen unbudgetierten weiteren Restart. Sie werden nicht pauschal verschluckt.

## Optionaler Kernel-Airbag

Ein großzügiger Hardcap mit MemoryMax=32G und MemoryOOMGroup=yes kann nach
separater Lastverifikation als letzte Barriere ergänzt werden. Er ist nicht Teil
dieser ersten Aktivierung.

Vorher muss nachgewiesen werden, dass legitime synchrone Kindprozesse und der
beobachtete Normalbetrieb genügend Abstand zu 32 GiB haben. Ein Hardcap ersetzt
den externen Guard nicht, sondern wäre nur dessen nachgelagerter Airbag.

## Bestehende passive Speichertelemetrie

Auf dem Live-Host läuft bereits der unabhängige systemweite Timer
`heim-pc-memory-pressure-snapshot.timer`. Sein Root-One-shot erfasst alle
30 Sekunden unter anderem:

* `MemAvailable`, Swap-Belegung und PSI;
* die größten Prozesse mit PID, Name, RSS, Swap und Cgroup;
* die größten Cgroups mit `memory.current`, `memory.swap.current` und
  OOM-Ereignissen.

Die Evidenz liegt begrenzt unter `/var/lib/heim-pc/memory-pressure/`. Dieser
Snapshot ist passiv und führt keine Prozessmutation aus.

Diese bestehende Laufzeittelemetrie wird von diesem Änderungspaket bewusst
**nicht dupliziert**. Ihre derzeit fehlende Verankerung im Heim-PC-Repo ist ein
separater Konvergenzpunkt; der neue Grabowski-Guard hängt für seine Entscheidung
nicht von diesem Snapshot ab, sondern liest systemd, `/proc` und die
Operator-Cgroup jeweils frisch.

## Docker-Loggrenze

config/runaway-guard.v1.json setzt für neue Container den lokalen,
größenbegrenzten Logging-Treiber mit 50 MiB Segmentgröße und drei Segmenten.

scripts/install_docker_log_policy.py ergänzt diese Werte konfliktvermeidend in
/etc/docker/daemon.json und bewahrt alle anderen Daemon-Einstellungen.
Bereits vorhandene abweichende Logwerte blockieren die Installation statt still
überschrieben zu werden.

## Installation und Sicherheitsgrenze

scripts/install_memory_pressure_guard.py installiert ausschließlich
commitgebundene Blobs.

Der Installer publiziert Guard-Skript und Policy unter

    /usr/local/lib/heim-pc/memory-pressure-guard/releases/<commit>/

und installiert ausschließlich

    /etc/systemd/system/heim-pc-grabowski-memory-guard.service

Es wird kein zusätzliches OOM-Killer-Paket installiert.

Der Installer trennt Installation, Enable und Start. **Jeder** Live-`--apply`
verlangt eine exakte `--expected-head`-Bindung; ein zufällig sauber
ausgecheckter Commit reicht nicht als Deployment-Autorität. Installationspfade
bleiben lexikalisch erhalten und werden komponentenweise descriptor-relativ mit
`O_NOFOLLOW` geöffnet. Derselbe verifizierte Parent-Directory-FD bleibt bis zum
atomaren Replace und Directory-`fsync` die Schreibautorität. Damit können weder
Symlink-Ancestors in einem `--system-root` noch ein späterer Pfadtausch einen
Release- oder Unit-Write aus dem deklarierten Root umlenken.

Für einen Live-Host werden zuerst nur die neuen inhaltsadressierten Release-
Dateien publiziert. Bevor eine bereits aktivierte **oder nur manuell aktive**
Unit ersetzt, neu aktiviert oder gestartet werden darf, führt der neue
commitgebundene Guard
`--preflight-only` aus. Dieser Modus liest den vollständigen persistenten State
einschließlich Schema, Ziel-Unit, Restart-Historie, Zähler, Circuit und
`pending_action`, beobachtet zugleich den realen Operator und führt dabei
weder State-Writes noch Prozessmutationen aus. Ein ungültiger persistenter State,
ein offener Circuit, eine ausstehende Aktion sowie eine aktuelle Restart- oder
Stop-Entscheidung blockieren fail-closed. Erst danach wird die Unit ersetzt.

`--start` verwendet absichtlich `systemctl restart`: Eine bereits aktive alte
Guard-Instanz darf nach einem Update nicht mit dem vorherigen Release weiterlaufen.
Der Abschlussbeleg verlangt anschließend `active`, eine gültige eigene Cgroup
und eine exakte `/proc/<MainPID>/cmdline`, die auf den neuen Commit-Release zeigt.
Der Receipt nennt dies `exact-release-process-observed` und kennzeichnet
`health_gate=pending-deployment-acceptance`: Type=simple beweist damit noch
keinen erfolgreichen Tick und keine stabile Gesundheit.

**Verbindlicher Deployment-/Acceptance-Gate:** Nach Installation über mehr als
zwei Sampleintervalle (aktuell länger als 30 Sekunden) beobachten. Zu Beginn und
Ende dieselbe Guard-PID samt procfs-Startzeit und unverändertes `NRestarts`
nachweisen; exakte Release-argv und eigene Cgroup müssen weiter stimmen.
Mindestens drei aufeinanderfolgende, zeitlich fortschreitende `latest.json`-
Events ohne Guard-Fehler sowie ein gültiger State ohne Pending/Circuit sind
erforderlich. Exit, Prozesswechsel, stagnierende/fehlende Events oder
Journalfehler verweigern Acceptance. Installer-Receipt allein genügt nicht.

Beispiel:

    sudo python3 scripts/install_memory_pressure_guard.py \
      --apply --enable --start --expected-head <commit>

Der Schutz gilt damit für:

* explizit begrenzte Hintergrundbefehle;
* Docker-Logwachstum nach Aktivierung der bestehenden Docker-Policy;
* den konkret belegten Grabowski-Hauptprozess-Runaway.

Die bereits vorhandene passive Root-Telemetrie bleibt eine getrennte
Beobachtungsschicht und wird hier nicht als installierter Effekt beansprucht.

Direkt gestartete andere Programme erhalten weiterhin kein pauschales
Cgroup-Limit. Ein weiterer globaler OOM mit einem anderen dominanten
Verursacher würde deshalb eine neue Evidenzbewertung erfordern.

## Bewusst nachgelagerte Arbeit

* **Cgroup-weites Child-Anon:** `memory.stat:anon` ist die passende
  cachefreie Messgröße für Kinder, aber die vorhandene 240-Sample-Historie
  enthält nur `memory.current` und Swap. Ein einzelner Livevergleich von
  Hauptprozess-RssAnon und Cgroup-anon sowie kleine beobachtete Child-RSS-Werte
  kalibrieren keine legitimen Job-Spitzen. Follow-up: die vorhandene passive
  Telemetrie um anon ergänzen, normale Child-Lasten auswerten, erst danach eine
  separate Schwelle reviewen. Dieser PR garantiert MainPID-Containment;
  ein Child-only-Runaway bleibt eine explizite Schutzlücke.
* **Release-Pruning:** separat mit nachgewiesenem Ausschluss des laufenden und
  des Recovery-Releases entwerfen. Kein Löschpfad in diesem Safety-Fix.
* **Interner Leak:** Ursachenanalyse in Grabowski bleibt unabhängig nötig.
