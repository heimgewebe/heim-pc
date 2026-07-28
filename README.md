# heim-pc

**Versioniertes Operatorium-Entrée für den lokalen Rechner – maschinenlesbar, mit Kartografie, Weltmodell und Drift-Orientierung.**

## Mission

`heim-pc` ist die versionierte Empfangshalle für Agenten und Menschen, die am lokalen Rechner-Kontext starten. Es beantwortet zuerst:

* Wo beginnt ein Maschinenoperator deterministisch?
* Welche lokalen Repositories und Primärquellen gelten?
* Welche lokalen Flächen bleiben tabu?
* Wo liegt die kanonische Ökosystemkarte?

Die bisherige Kartografie-Rolle bleibt erhalten, wird aber unter diese Entrée-Rolle eingeordnet.

## These / Antithese / Synthese

**These:** Dieses Repository ist der richtige Ort für ein Operatorium-Entrée, weil es bereits das lokale Weltmodell für heim-pc, Repositories, Zonen und Drift beschreibt.

**Antithese:** Es darf nicht zu einer zweiten Ökosystemkarte, einem Home-Spiegel, einem stillen Inhaltsdump oder einem zweiten Runtime-Statusspeicher werden.

**Synthese:** `heim-pc` pflegt kleine, reviewbare Einstiegs-, Locator- und Orientierungsartefakte. Der Systemkatalog bleibt der kanonische Ort stabiler Ökosystemsemantik. Live-Zustand bleibt bei Grabowski, Bureau, GitHub, CI, systemd, Logs und Healthchecks. Das Home-Verzeichnis bekommt nur kurze lokale Projektionen.

## Operator- und Menschenrolle

* ChatGPT über Grabowski ist der Operator für Prüfung und Ausführung.
* Der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen; er soll nicht als Shell-Ausführer dienen.
* Maschinenlesbare Verträge und frische Primärquellen haben Vorrang vor Prosa.

## Wahrheitsordnung

1. Grabowski-Laufzeitidentität, konkrete Receipts, GitHub, CI, PR-Diffs und aktuelle Runtime-Belege sind Primärquellen für gegenwärtigen Zustand.
2. `manifest/operator-entry.v1.json` ist die kanonische lokale Einstiegskette und Locator-Quelle für heim-pc.
3. Der statische Systemkatalog ist die kanonische Quelle für Systemzwecke, Grenzen, Wahrheitsbesitz, stabile Beziehungen und systemweite Einstiegspunkte.
4. Bureau ist die Primärquelle für Aufgaben, Claims und Receipts.
5. `manifest/repo-index.yaml` ist die Quelle für kanonische Dokumente in diesem Repository.
6. `SYSTEM_MAP.md` wird daraus generiert und ist nur die Repo-Dokumentationskarte.
7. Lokale Pointer im Home-Verzeichnis sind Wegweiser, keine versionierte Wahrheit.
8. `state/index.json` und `state/repos.json` enthalten Placeholder-Daten und sind im Maschinenvertrag ausdrücklich als aktuelle Wahrheit ausgeschlossen.

## Erster Einstieg

* [Maschinenvertrag](manifest/operator-entry.v1.json) – kanonische lokale Einstiegskette, Primärquellen und Checkout-Lokatoren
* [.ai-context.yml](.ai-context.yml) – kompakte maschinenlesbare Rollen- und Einstiegsklassifikation
* [AGENTS.md](AGENTS.md) – Agenten-/LLM-Einstieg mit Arbeitsregeln und Stop-Kriterien
* [Operatorium-Entrée](architecture/operatorium-entry.md) – normative Rolle dieses Repositories
* [Home-Entry Runtime Note](runtime/home-entry.md) – lokale Projektion, Pointer-Logik und Grenzen
* [Software-Inventar](runtime/software-inventory.md) – operatorisch relevante Programme, Dienste und bekannte Caveats
* [Programminventar](runtime/program-inventory-summary.md) – kompakte Übersicht aus Root-/Paket-/Prozessscan; Rohlisten bleiben lokal
* [SYSTEM_MAP.md](SYSTEM_MAP.md) – generierte Karte der kanonischen heim-pc-Dokumentation
* [Sicherheit](architecture/security.md) – Datenpolitik und Tabuflächen

## Kanonischer Maschinenstart

Die versionierte Quelle ist `manifest/operator-entry.v1.json`. Öffentliche Pfade sind als `${HOME}`-Templates formuliert und müssen vor einem Dateizugriff gegen das absolute Home des Operatorprozesses aufgelöst werden. Der Vertrag wird byteidentisch nach `~/.config/heimgewebe/operator-entry.v1.json` projiziert. Zusätzlich werden kurze lokale Pointer als `~/AGENTS.md`, `~/repos/AGENTS.md` und `~/README.md` installiert.

```bash
python3 scripts/install_operator_entry.py                              # nur Plan, keine Mutation
python3 scripts/install_operator_entry.py --apply                      # nur ohne abweichende bestehende Pointer
python3 scripts/install_operator_entry.py --apply --replace-existing   # nach Prüfung des Plans
python3 scripts/check_operator_entry.py --require-installed
```

Der Vertrag enthält absichtlich keine Live-Gesundheit, Taskpriorität, Branchstände oder Merge-Reife. Er nennt nur die Startsequenz, lokale Lokatoren, Primärquellen, ausgeschlossene Scheinquellen und Sicherheitsgrenzen.

Der Installer arbeitet fail-closed: Er sperrt parallele Installationen, bindet Writes an den gelesenen Vorzustand, öffnet die jeweilige letzte Pfadkomponente mit `O_NOFOLLOW`, lehnt erkannte Symlink-Ziele und -Eltern ab und ersetzt abweichende bestehende Pointer nur mit `--replace-existing`. Ein absichtlicher paralleler Austausch eines übergeordneten Verzeichnisses ist damit nicht vollständig ausgeschlossen. Vor dem atomaren Ersetzen werden Backups unter `~/.local/state/heim-pc/operator-entry-backups/` angelegt. Der maschinenlesbare Installationsbeleg liegt unter `~/.local/state/heim-pc/operator-entry-install-receipt.v1.json`. Die vier Dateien werden einzeln atomar geschrieben; eine atomare Gesamttransaktion über alle Dateien wird ausdrücklich nicht behauptet.

Für ChatGPT über Grabowski beginnt jede neue Operatorroute mit:

1. `grabowski_status(view="evidence")` für Runtime-Identität, Integrität und Connector-Warnungen;
2. `grabowski_agent_bootstrap()` für den gebundenen Ausführungsvertrag;
3. `grabowski_context(profile="concise")` für kompakten Operator-Kontext ohne Prosa als Livewahrheit;
4. Lesen des installierten JSON-Vertrags;
5. Auflösen von `${HOME}` gegen das absolute Operator-Home; unaufgelöste Variablen blockieren Dateizugriffe;
6. Klassifikation als Einzelrepo-, systemweiter, Host-, Task- oder Historienfall;
7. gezieltes Lesen der referenzierten Primärquellen und abschließender zielbezogener Live-Read vor Mutation.

## Host-Health- und Log-Remediation

`config/host-health-remediation.v1.json` bindet die schmale persistente
Hostkonfiguration an überprüfbare Grenzwerte und Firmware-Identitäten.
`scripts/install_host_health_remediation.py` zeigt standardmäßig nur den Plan. Ein
späterer, eigens autorisierter Lauf mit `--apply --expected-head <commit>` installiert
die Dateien commitgebunden, erstellt vor dem Ersetzen abweichender Dateien ein
inhaltsadressiertes Backup und aktiviert oder startet keine Unit. Dieser PR selbst
deployt nichts und ändert weder `/etc` noch Root-Zustand.

Die installierbaren Teile haben folgende Grenzen:

* Der systemweite User-Unit-Drop-in setzt `ConditionUser=!gdm` für die
  Distribution-Unit `fluidsynth.service`. Die globale Aktivierung bleibt bestehen,
  die Bedingung ist für `alex` wahr, und nur GDM wird übersprungen. Eine Prüfung des
  GDM-Ergebnisses ist erst nach Neustart seines User-Managers oder nach einem Reboot
  aussagekräftig.
* `cpu-governor.service` nutzt einen Wrapper, der
  `system76-power profile performance` ausführt. Nur ein Fehler mit allen Merkmalen
  „SCSI host profiles“, fehlendes Power-Policy-Ziel und `ENOENT` wird als harmlos
  eingeordnet. Auch dann muss die unabhängige Abschlussabfrage exakt
  `Power Profile: Performance` melden; andere Fehler bleiben Fehler.
* `heim-pc-mce-edac-monitor.timer` betrachtet höchstens 2.000 Kernel-Journaleinträge
  aus 24 Stunden über Boot-Grenzen hinweg, läuft höchstens 30 Sekunden alle sechs
  Stunden und ist auf 10 Prozent CPU sowie 64 MiB RAM begrenzt. Der Installer
  liefert dazu ein journald-Drop-in mit `Storage=persistent`,
  `SystemMaxUse=2G`, `SystemKeepFree=20G` und `MaxRetentionSec=14day`. Das zuvor
  vorgesehene 512-MiB-Limit lag unter dem beobachteten Live-Journal-Footprint von
  rund 1019 MiB, der nur drei Boots enthielt, und hätte deshalb das Ziel
  brauchbarer Boot-übergreifender Evidenz konterkariert. 2 GiB entsprechen auf
  dem 2-TB-Systemdatenträger ungefähr 0,1 Prozent und bleiben eine explizite
  Obergrenze; die Keep-free-Schranke schützt bei weniger als 20 GiB freiem Platz
  zusätzlich vor Datenträgerdruck. Das 14-Tage-Alterslimit begrenzt die Evidenz
  außerdem zeitlich. Der Monitor erzeugt nur einen deduplizierten, knappen
  Rekurrenzbericht unter
  `/var/lib/heim-pc/host-health/mce-edac-report.v1.json`. Er führt keinen
  Belastungstest durch und diagnostiziert keine Hardwareursache automatisch.
  Die ID-Retention deckt die vollständige maximale Journalabfrage ab, damit
  unveränderte Einträge innerhalb des Fensters nicht erneut gezählt werden.
* `heim-pc-host-health kvm-svm` trennt die Ebenen: Fehlt bei AMD das CPU-Flag
  `svm`, liegt der Befund vor der KVM-Modulladephase und weist auf in UEFI
  deaktivierte oder anderweitig verborgene Virtualisierung. Ist `svm` vorhanden,
  aber `kvm_amd`, das generische `kvm`-Modul oder `/dev/kvm` fehlt, wird dies
  stattdessen als Kernel-/Modul-/Device-Problem berichtet. Das Werkzeug ändert
  keine BIOS-Einstellung.

### Offline-sicherer FAT-Check

Die laufende EFI- oder Recovery-Partition darf nicht repariert werden. Der Operator
bootet dafür ein separates Recovery-/Live-System, löst das exakte Blockgerät über
`lsblk` und `findmnt` auf und stellt sicher, dass es nicht gemountet ist. Das
Werkzeug prüft diese Bedingung direkt vor `fsck.fat` zweimal, unmountet nie
automatisch und verweigert andere Dateisystemtypen:

```bash
heim-pc-host-health fat /dev/<exakte-fat-partition>
heim-pc-host-health fat /dev/<exakte-fat-partition> --repair --confirm-offline-repair
```

Der erste Aufruf verwendet ausschließlich `fsck.fat -n`: Returncode 0 bedeutet
sauber, Returncode 1 meldet gefundene Inkonsistenzen und ist kein Erfolg,
Returncodes ab 2 bleiben Fehler. Der zweite verwendet `fsck.fat -a` nur nach der
expliziten Offline-Bestätigung. Liefert der Reparaturpass 0 oder 1, folgt zwingend
ein zweiter, read-only `fsck.fat -n`-Pass; nur dessen Returncode 0 gilt als
verifizierter Erfolg. Der JSON-Bericht bewahrt beide Returncodes sowie pro Pass
auf 4.096 Byte je stdout/stderr begrenzte Ausgabe. Ein gleichzeitig durch einen
anderen privilegierten Prozess ausgeführter Mount kann nicht rennfrei
ausgeschlossen werden; deshalb bleibt das separate Recovery-System Teil der
Sicherheitsgrenze. Eine online unter `/boot/efi` eingehängte Partition ist
ausdrücklich kein zulässiges Reparaturziel.

### BIOS-Vorbereitung ohne Flash

Der Verifier akzeptiert ausschließlich das Board `ROG STRIX B550-F GAMING` und
bindet die Vorbereitung an die beobachtete Ausgangsversion `3202`. Der
Standardkanal ist das stabile Ziel `3636` mit SHA-256
`BCB430187AD366238908C6EC6E7715C9EB056E77A620333CCBCCEDA42FB25082`.
Das Beta-Ziel `3641` muss ausdrücklich gewählt werden und hat SHA-256
`FBA248F9F6099E55D4F194376D34C652F2971A44875BDA73ED8FEF34418C317B`.

```bash
heim-pc-host-health bios --target stable --package /pfad/zum/ASUS-3636.zip
heim-pc-host-health bios --target beta --package /pfad/zum/ASUS-3641.zip
```

Die von ASUS veröffentlichten SHA-256-Werte binden die vollständigen ZIP-Pakete,
nicht die darin enthaltenen CAP-Dateien. Das Werkzeug liest Board und laufende
BIOS-Version, verlangt das lokale ZIP-Paket und prüft zuerst dessen Paketdigest.
Danach inspiziert es das Archiv ohne Extraktion: Für das gewählte Ziel müssen
exakt die erwartete versionsgebundene CAP-Datei und `BIOSRenamer.exe` enthalten
sein. Traversal-Namen, Symlinks, Duplikate, verschlüsselte oder unerwartete
Mitglieder werden abgelehnt. Der CAP-SHA-256 wird beim Lesen aus dem verifizierten
Paket lokal abgeleitet und als solcher berichtet; er ist kein separat von ASUS
veröffentlichter Digest. Das Werkzeug lädt nichts herunter, extrahiert nichts,
schreibt keine EFI-Variable und flasht nicht. Ein Paket-Hash-Treffer belegt nur
die Bindung an den festgelegten Digest, nicht den Erfolg oder die Freigabe eines
Firmware-Updates.

Firmware-Flash und SVM-Aktivierung bleiben absichtlich Reboot-/UEFI-Operationen:
Die Firmware muss das Board außerhalb des laufenden Betriebssystems neu
initialisieren, und das CPU-Flag `svm` wird erst beim nächsten Boot exponiert.
Ein laufender Kernel kann eine im UEFI deaktivierte SVM-Funktion weder verlässlich
noch portabel einschalten. Automatisches Flashen oder ein behaupteter
„BIOS-Fix“ aus dem Betriebssystem würde deshalb die Recovery-, Stromversorgungs-
und physische Bestätigungsgrenze umgehen und ist nicht Bestandteil dieser
Remediation.

## Direkter Systemkatalog-Pointer

Die systemweite stabile Semantik liegt nicht in diesem Repository, sondern im Systemkatalog:

* Agenteneinstieg: `~/repos/systemkatalog/AGENTS.md`
* Lesbare Katalogansicht: `~/repos/systemkatalog/rendered/system-catalog.md`
* Generierte Registry-Karte: `~/repos/systemkatalog/rendered/ecosystem-registry-map.mmd`
* Commit- und hashgebundener Verbraucher-Lieferschein: `~/repos/systemkatalog/rendered/ecosystem-map-artifact-manifest.json`
* Deterministische Abfrage: `python3 ~/repos/systemkatalog/scripts/systemkatalog_query.py system <name>`

Leitstand zeigt die Karte read-only an. Für aktuelle Aufgaben, PRs, CI oder Runtime-Gesundheit gelten weiterhin Bureau, GitHub, CI, Grabowski, systemd, Logs und Healthchecks.

## Gemeinsamer Agenteneinstieg und Drift-Watchdog

`config/agents/repos-root-AGENTS.md` ist die versionierte Vorlage für `~/repos/AGENTS.md`. Sie beginnt beim Host-Maschinenvertrag und verweist nur bei repositoryübergreifenden Systemfragen auf den Systemkatalog. Dadurch wird bei gewöhnlicher Einzelrepo-Arbeit kein unnötiger Gesamtkontext geladen.

Der stündliche `systemkatalog-drift-watch.timer` prüft unabhängig vom GitHub-Zeitplan Organisations-, Fleet- und Primärquellendrift. Er darf keine Semantik schreiben oder mergen. Bei materieller Drift registriert er höchstens einen deduplizierten Bureau-Kandidaten und legt Bericht sowie proposal-only Vorschlag lokal unter `~/.local/state/heim-pc/systemkatalog-drift-watch/` ab.

```bash
python3 scripts/install_systemkatalog_reliability.py          # Plan anzeigen
python3 scripts/install_systemkatalog_reliability.py --apply --enable
```

## Goldene Regel

> **Klein committen, groß auslagern. Privatflächen nicht zur Orientierung opfern.**

* Rohdaten → lokal, CI-Artefakte oder Releases, nicht in Git-Historie
* Nur kleine, reviewbare, kanonische Artefakte im Repository
* Keine Secrets, Browserprofile, Keyrings oder privaten Inhaltsflächen lesen oder ausgeben
* Keine zweite Systemkarte neben dem Systemkatalog pflegen
* Keine Live-Zustände in den statischen Operator-Entry-Vertrag kopieren
* Placeholder-Dateien nicht als Wahrheit behandeln

## Struktur

```text
heim-pc/
├─ .ai-context.yml                    # Maschinenlesbare Rollen- und Einstiegsklassifikation
├─ AGENTS.md                          # Agenten-/LLM-Entrée
├─ architecture/                      # Normatives Wissen (Konzepte, Policies, Security)
├─ runtime/                           # Reality/Observations und lokale Betriebsnotizen
├─ manifest/operator-entry.v1.json    # Kanonischer lokaler Maschinenstart
├─ manifest/repo-index.yaml           # Kanonische Dokumente und Checks
├─ config/agents/                     # Installierbare lokale Pointer
├─ state/                             # Legacy-Fixtures und nur quellengebundene Beobachtungen
├─ timeline/                          # Chronologische Historie (komprimierbar)
├─ snapshots/                         # Aggregationen & Pointer auf große Daten
├─ contracts/                         # Verweis auf zentrale Metarepo-Verträge
└─ .wgx/                              # WGX-Integration (Fleet-konform)
```

## Kartografie-Rolle

Heim-PC bleibt die Verbindung zwischen lokalem Dateisystem und Heimgewebe-System. Es dient weiterhin als:

* Kartografie des Rechners: Dateisystem, Repositories, Zonen, Drift,
* Heimgewebe-taugliche Orientierung durch Zonen, Lokatoren und quellengebundene Inventare,
* Historie und Drift-Tracking durch Timeline-Daten,
* strukturiertes Wissensmodell statt Dump-Repo.

Diese Rolle ist aber operativ begrenzt: Kartografie bedeutet Metadaten, Struktur und Pointer, nicht private Inhalte. Atlas unterscheidet dabei logische Dateilänge von tatsächlich belegten Dateisystemblöcken; keine der beiden Größen ist ein Backup- oder Wiederherstellungsbeleg. Konventionelle Core-Dump-Namen bleiben aus Standardkartierungen ausgeschlossen. Atlas löscht sie nicht und ist keine Speicherbereinigung.

## Zustandsartefakte erzeugen

GitHub Actions kann den lokalen Rechner nicht als Primärquelle beobachten. Volatile Inventare und Driftberichte werden deshalb lokal außerhalb Git erzeugt. Ein Ergebnis darf erst versioniert oder als Operatorwahrheit genutzt werden, wenn Generatorversion, UTC-Zeitpunkt, erlaubte Quellen, Hashbindung, Frischegrenze und ausgeschlossene Behauptungen maschinenlesbar enthalten und getestet sind.

`state/index.json` und `state/repos.json` erfüllen diesen Vertrag derzeit nicht. Sie bleiben Legacy-Fixtures und werden weder durch CI-Frischechecks noch durch die aktive Contract-Validierung als aktuelle Wahrheit behandelt.

## Validierung

Der `heim-pc-validate` Workflow prüft automatisch:

* JSON/YAML-Struktur,
* Unit Tests,
* Syntax- und Contract-Smokes,
* Repo-Index-Konsistenz,
* Dokument-Review-Alter,
* Struktur und statische Grenzen des Operator-Entry-Vertrags,
* Übereinstimmung der kompakten `.ai-context.yml`-Klassifikation,
* `${HOME}`-Resolververtrag und Ausschluss aufgelöster privater Hostpfade aus der öffentlichen Vorlage,
* ob `SYSTEM_MAP.md` aus `manifest/repo-index.yaml` regenerierbar und aktuell ist.

`python3 scripts/check_operator_entry.py --require-installed` prüft zusätzlich lokal, ob der Maschinenvertrag und alle drei Pointer installiert und bytegleich sind. Der persistente Installationsbeleg muss an den aktuellen Vertrags-Hash gebunden sein und die attestierten Zieldateien müssen weiterhin exakt übereinstimmen.

Ein grüner Lauf belegt Struktur- und Projektionskonsistenz. Er belegt nicht automatisch Runtime-Korrektheit, fachliche Vollständigkeit, Connector-Frische oder Merge-Reife.

## Documentation Zones

The documentation follows a strict zone model governed by `manifest/repo-index.yaml`:

* **`entry`**: top-level agent entry documents.
* **`norm`**: normative knowledge — how things should be.
* **`reality`**: observational knowledge — how things are currently described or observed.

For a complete overview of all canonical documents, their review status, and dependencies, see the auto-generated [SYSTEM_MAP.md](SYSTEM_MAP.md).

## Mehr erfahren

* [Weltmodell-Konzept](architecture/model.md) – Was ist das Weltmodell?
* [Operatorium-Entrée](architecture/operatorium-entry.md) – Wie heim-pc als lokale Empfangshalle funktioniert
* [Zonen & Bedeutungen](architecture/zones.md) – Semantische Bereiche
* [Drift-Definition](architecture/drift-policy.md) – Was bedeutet Drift und wie wird er erkannt?
* [Sicherheit](architecture/security.md) – Datenpolitik, Tabuflächen und Pfadgrenzen
* [Contracts](contracts/README.md) – zentrale Data-Schemas und Versionierung

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX reusable workflows:

* **Guard**: Lint-Checks via `heimgewebe/wgx`
* **Smoke**: Konsistenz-Tests über Index, Pfade und Struktur
* **Validate**: Struktur-Validierung und Placeholder-Warnung

Workflows referenzieren zentrale WGX-Templates, um Fleet-Drift zu vermeiden.

## Lizenz

Siehe LICENSE-Datei im Repository.
