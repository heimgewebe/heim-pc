---
id: nixos-executor-2026
role: norm
status: canonical
last_reviewed: 2026-09-02
depends_on:
  - system-constitution
  - model
  - security
  - storage-lifecycle
  - managed-builds
  - network-identity
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# NixOS Executor-Profil 2026

## Status und Grenze

Dieses Dokument konkretisiert die `system-constitution` für den bevorzugten Executor 2026.

**Ziel-Executor:** NixOS Stable 26.05.

Das Profil beschreibt den Sollschnitt für eine spätere NixOS-Migration. Es autorisiert keine Installation, keine Partitionierung, kein Firmware-Update und keinen Eingriff in den produktiven Datenträger.

Das Profil wird mindestens bei jedem NixOS-Stable-Wechsel sowie bei einem materiellen Wechsel von Nix-/Nixpkgs-, Home-Manager-, Storage-, Secret- oder Trust-Bausteinen neu geprüft. Sein Datum ist keine Dauerfreigabe.

Die Systemverfassung bleibt höher priorisiert. Wird ein Detail dieses Profils unzweckmäßig, darf das Profil geändert werden, ohne die Verfassung umzuschreiben.

## 1. Control Release Set

Die Control Plane wird als gemeinsam getestetes Release-Set geführt. Mindestens gebunden werden:

- Nix-Implementierung und deren relevante Feature-Flags;
- Nixpkgs-Revision;
- NixOS-Release;
- Home-Manager-Revision;
- Disko-Revision;
- verwendete Systemmodule;
- freigegebene Binär-Caches und deren Vertrauensschlüssel;
- weitere sicherheits- oder bootrelevante Inputs.

Host und Home Manager referenzieren dieselbe freigegebene Nixpkgs-Basis. Sie werden dennoch getrennt evaluiert und aktiviert.

Ein Projekt darf davon unabhängig eine eigene Nixpkgs-Revision, Toolchain oder einen eigenen OCI-Digest besitzen.

## 2. Entrypoints und Module

Kanonisch ist die Modulstruktur, nicht der Entrypoint.

`flake.nix`, `system.nix` oder zukünftige Einstiegspunkte dürfen nur Adapter auf dieselben Host-/User-Module sein. Sie dürfen keine zweite fachliche Konfiguration entwickeln.

Für 2026 ist ein dünner Flake-Adapter zulässig und praktisch, weil das Nix-Ökosystem vielfach flake-first ist. Der Kern darf jedoch nicht von Determinate-spezifischen Schemas, Lix-Plugin-Semantik oder anderen Implementierungsdetails abhängen, die einen späteren Adapterwechsel unnötig erschweren.

## 3. Host- und User-Domäne

### Host

Der NixOS-Host verwaltet nur systemfundamentale Funktionen:

- UEFI/Boot;
- Kernel und Initrd;
- Storage- und Entschlüsselungsbasis;
- CPU-, Mainboard- und Geräteunterstützung;
- NVIDIA-Treiber und grafische Basis;
- Netzwerk;
- PipeWire/ALSA/BlueZ-Basis;
- Security und lokale Trust-Konfiguration;
- Podman beziehungsweise die freigegebene OCI-Runtime;
- fundamentale systemweite Dienste;
- Generatoren/Installer für Declared Facts und notwendige Runtime-Checks.

Der Kernel- und NVIDIA-Zweig werden explizit gepinnt beziehungsweise freigegeben. Sie werden nur gemeinsam mit den Hardware-Gates fortgeschrieben. Ein Kernel-Bump ist keine beiläufige Paketaktualisierung.

### User

Home Manager wird als eigenständige Aktivierungsdomäne geführt. Typische Zuständigkeiten:

- Shell und Terminal;
- Editor und Git-Userkonfiguration;
- Desktop-Dotfiles und userseitige XDG-Konfiguration;
- userseitige Werkzeuge;
- `direnv`-Integration für projektlokale Umgebungen.

Host und User teilen das Control Release Set, aber ein kaputter Dotfile-/Editor-Stand darf keinen Host-Deploy erzwingen.

Grenzfälle wie Portals, DConf, Fonts, PipeWire-User-Units oder Desktop-Integration werden explizit einer Seite zugeordnet und getestet; sie dürfen nicht durch zufällige Doppelverwaltung entstehen.

## 4. Project Plane und Workloads

### Nix-Devshells

Strukturierte Entwicklungsprojekte verwenden projektgebundene Devshells, vorzugsweise mit `direnv`, wenn dies den Workflow vereinfacht.

Geeignet sind unter anderem:

- Rust-Toolchains;
- Node/SvelteKit;
- reproduzierbare Compiler-/Buildumgebungen;
- projektlokale CLI-Abhängigkeiten.

Projektpins gehören in die jeweiligen Projekte, nicht in das Host-Release-Set.

### OCI / Podman

OCI ist die bevorzugte Isolationsschicht für Workloads mit eigenem Release-Takt oder fremder Abhängigkeitswelt, insbesondere:

- opake Vendor-Images;
- stark wechselnde Python-/ML-Stacks;
- geeignete lokale KI-Experimente;
- Dienste, deren Containervertrag stabiler ist als ihre Nix-Verpackung.

Nicht jeder Dienst muss containerisiert werden. Die Entscheidung folgt Fehlerdomäne, Wartbarkeit und Schnittstellenklarheit, nicht Container-Purismus.

### Untrusted Build- und Install-Hooks

`build.rs`, `npm`-/`pnpm`-Lifecycle-Skripte, Python-Buildbackends und vergleichbare fremde Projekt-Hooks gelten als ausführbarer Workload-Code. Sie erhalten **keine implizite Secret- oder Host-Administrationsautorität** nur weil sie in einer Devshell laufen.

Für nicht ausreichend vertraute Hooks wird eine isolierte Ausführung vorgesehen, beispielsweise über Container, gehärtete systemd-Einheiten oder eine getrennte Ausführungsidentität. Insbesondere dürfen solche Workloads keinen blanket-Zugriff auf SSH-/GPG-/Password-Store-/Secret-Material und keine pauschale `wheel`-, `NOPASSWD`- oder Nix-`trusted-users`-Berechtigung erhalten.

## 5. NVIDIA, CUDA und CDI

Für das 2026-Profil ist die RTX 4070 Ti SUPER der erwartete GPU-Acceptance-Anker. Diese Modellbezeichnung ist **kein Liveinventar**; vor einem Cutover wird sie durch einen frischen quellengebundenen Hardware-Receipt bestätigt oder das Profil vor der Freigabe angepasst. Der bestätigte Host besitzt Treiber und Gerätelayer; experimentelle CUDA-/Python-/ML-Stacks gehören nicht global in den Host.

GPU-fähige OCI-Workloads verwenden CDI als Host/Container-Schnittstelle. Das Profil bindet **keinen konkreten CDI-Dateinamen**. Acceptance prüft die veröffentlichte CDI-Geräteidentität über die Runtime selbst.

Für NixOS 2026 ist `hardware.nvidia-container-toolkit` der bevorzugte Integrationspfad, sofern der gewählte Nixpkgs-Pin und die reale Hardwareprüfung ihn bestätigen.

CUDA-Toolchains werden bevorzugt projektgebunden oder workloadgebunden bereitgestellt. Eine globale Aktivierung von CUDA in beliebigen Host-Ableitungen ist zu vermeiden.

## 6. Storage-Profil

### Zielaufbau

Bevorzugtes 2026-Profil:

```text
GPT
├── EFI System Partition
├── Recovery-Oberfläche
└── LUKS2
    └── Btrfs
        ├── @root
        ├── @nix
        ├── @persist
        ├── @home
        ├── @data
        └── @containers
```

Disko beschreibt die produktive Zieltopologie deklarativ.

Die genaue Größe und Position der Partitionen ist keine Verfassungsinvariante und wird erst aus einem frischen Datenträgerinventar und einem gesonderten Migrationsplan festgelegt.

### Root

`@root` wird so vorbereitet, dass ein späterer deterministischer Reset beziehungsweise Impermanence-Light möglich ist.

Ein tmpfs-Root ist **kein** Startziel. Die erste produktive Stufe darf ein persistentes beziehungsweise Btrfs-basiert zurücksetzbares Root verwenden.

Vollständige Impermanence wird erst aktiviert, nachdem die tatsächlich nötigen persistenten Systempfade beobachtet, begründet und getestet sind.

### Nix Store

`@nix` ist persistent und getrennt vom zurücksetzbaren Root. `/nix/store`, GC-Roots und Generationen werden vor dem produktiven Cutover als **eigene verwaltete Speicherproduzenten** in die bestehende Storage-Lifecycle-/Budgetlogik aufgenommen. Nix-GC darf nicht als ungebundener zweiter Cleanup-Kanal neben `storage-lifecycle` entstehen.

Generationen und Store-Garbage-Collection erhalten eigene Retention-/Budgetregeln. Mindestens die aktuell laufende, die konfigurierte Boot-Default- und eine nach Hardware-Gates bekannte funktionierende Recovery-Generation bleiben geschützt. Ein `--delete-older-than`-ähnlicher Automatismus darf diese Schutzmenge nicht implizit zerstören.

Freier Speicher oder ein Pressure-Signal allein ist keine Löschfreigabe. Vor und nach GC werden Schutzmenge, GC-Roots, Wirkung und tatsächlich gewonnener Speicher quellengebunden zurückgelesen und receipted.

### Persist

`@persist` ist eine Whitelist für **Systemzustand**. Typische Kandidaten können Machine-ID, Hostkeys, notwendige Netzwerkidentitäten und ausdrücklich genehmigte Systemzustände sein.

`@persist` ist ausdrücklich **nicht** die Daten-Domäne: Datenbanken, zustandsbehaftete Service-Volumes und andere nicht reproduzierbare Workload-Daten gehören nach `@data`, nicht nach `@persist` oder `@containers`.

Die Aufnahme eines Pfads ist eine reviewbare Graphänderung. Nach einem Fehler wird nicht reflexartig ein Verzeichnis persistiert.

### Home, zustandsbehaftete Daten und Container-Cache

`@home` bleibt persistenter Nutzdatenraum und ist kein Nix-Systemgraph.

`@data` ist die bevorzugte eigene **Daten-Domäne** für zustandsbehaftete Service- und Workload-Daten, insbesondere Datenbanken oder Container-Volumes, deren Verlust nicht durch einen Rebuild behoben werden kann. Das Subvolume auf derselben SSD ist ausdrücklich **kein Backup**. Solche Daten werden klassifiziert und in den Off-host-Restore-Vertrag aufgenommen.

`@containers` enthält nur regenerierbare OCI-Images/-Layer, Build-Cache und ausdrücklich als entbehrlich klassifizierte Volumes. Zustandsbehaftete Daten dürfen nicht still in diese Lifecycle-Domäne geraten. CoW bleibt Standard. `nodatacow` wird nicht pauschal auf das Subvolume gesetzt. NOCOW/+C wird nur für gemessene konkrete Write-heavy-Verzeichnisse nach dokumentiertem Trade-off eingesetzt.

### Btrfs- und Lifecycle-Kompatibilität

Bestehende Cleanup-Verträge, die einen Tree vor dem Löschen per `rename(2)` atomar in Quarantäne verschieben, dürfen durch das neue Subvolume-Layout nicht gebrochen werden. Für jeden solchen Pfad wird vor Cutover belegt, dass Quelle und Quarantäne **rename-kompatibel** sind; ein `EXDEV`-Pfad blockiert die Migration dieses Producers, bis Layout oder Lifecycle-Implementierung angepasst und getestet sind.

Btrfs-Kompression, Reflinks und Snapshots trennen logische Größe, belegte Blöcke und tatsächlich rückgewinnbaren Speicher. Inventarwerte wie `st_blocks` oder apparent size dürfen deshalb nicht als garantierter Reclaim ausgegeben werden. Cleanup-/GC-Receipts vergleichen den realen Dateisystem-Freiplatz beziehungsweise eine Btrfs-spezifisch geeignete Belegungsmetrik vor und nach Wirkung.

Snapshots von regenerierbaren Cache-/Buildflächen werden nur eingeführt, wenn ihr Retention- und Reclaim-Effekt explizit im Storage-Lifecycle berücksichtigt ist.

## 7. Recovery und Backup

Die produktive Migration darf den bisherigen Recovery-Wert nicht verschlechtern.

Das Zielprofil verlangt zwei verschiedene Recovery-Ebenen:

1. **Host-unabhängiger Boot-/Recovery-Pfad:** nutzbar bei defekter NixOS-Generation oder beschädigtem Root; nicht abhängig von Grabowski, Bureau oder Netzwerk.
2. **Off-host-Datenrestore:** nicht reproduzierbare Daten und benötigtes Recovery-Material müssen von einem anderen physischen oder externen Speicherort wiederherstellbar sein. Dazu gehören mindestens die relevanten `/home`-Daten, die Offline-Secret-Recovery-Identität, für das Verschlüsselungsdesign notwendige Recovery-Metadaten beziehungsweise Header-Sicherungen sowie die für fail-closed Provenienz benötigte Receipt-Klasse unter `~/.local/state/heim-pc/`, soweit diese nicht anderweitig rekonstruierbar ist.

Der Restore-Test misst nicht nur „Datei vorhanden“, sondern beweist einen repräsentativen Wiederanlauf und dokumentiert RPO/RTO beziehungsweise bewusst akzeptierte Grenzen.

### Offline-Systemrekonstruktionssatz

Zusätzlich wird off-host ein verifizierter, **netzunabhängiger Rekonstruktionssatz** gehalten. Er muss zwei Ebenen abdecken: einen kleinen Recovery-Bootpfad für Diagnose/Restore und mindestens **eine vollständige bekannte funktionierende Host-/Control-System-Closure**, mit der der deklarierte Host-Basiszustand ohne produktive System-SSD und ohne Netzwerk wieder bootfähig hergestellt werden kann.

Der Satz enthält mindestens ein bootfähiges Recovery-/Installationsmedium, die gepinnte Host-Konfiguration beziehungsweise einen hashgebundenen Source-Snapshot, das zugehörige Control-Release-Set/Lock, die notwendigen Trust-Roots, die für Storage-/LUKS-/Restore-/Nix-Recovery nötigen Werkzeuge sowie die verifizierte bekannte Host-/Control-Closure einschließlich ihrer zum Booten und Aktivieren benötigten Store-Pfade. **Projekt-, Devshell-, Modell-, Container-Image- und sonstige Workload-Closures gehören nicht zu diesem Offline-Minimum** und dürfen nach Wiederherstellung eines vertrauenswürdigen Netzpfads reproduzierbar nachgezogen werden.

Der Satz wird nach materiellen Control-Release-Änderungen erneuert und regelmäßig auf einem entbehrlichen Ziel oder einer gleichwertig isolierten Recovery-Fläche mit **Netzwerk aus und produktiver System-SSD nicht verfügbar** restore-getestet. Das Offline-Gate ist erst bestanden, wenn aus dem Recovery-Medium die gespeicherte bekannte Host-/Control-Closure auf ein Ersatz-/Testziel übertragen, als freigegebene Systemgeneration aktiviert und erfolgreich gebootet wurde; der Readback bindet die gebootete Closure an die gespeicherte freigegebene Closure-Identität. Ein bloßes Erreichen einer Recovery-Shell genügt nicht.

Eine Recovery-Partition auf demselben Datenträger kann die erste Ebene unterstützen, ersetzt aber keinen Off-host-Backup-Pfad gegen Datenträgerausfall.

Vor jeder destruktiven Neuaufteilung des einzigen produktiven Datenträgers müssen mindestens erfüllt sein:

- frisches Blockgeräte-/Mount-Readback;
- exakte Bindung des Zielgeräts;
- verifizierter Off-host-Backup- und Restore-Test für kritische Nutzdaten;
- unabhängiges bootbares Recovery-Medium;
- dokumentierter Rückweg beziehungsweise akzeptierter Point of No Return;
- eigener, explizit autorisierter Storage-Migrationsplan.

Ein separater Testdatenträger bleibt der bevorzugte Falsifikationspfad, ist aber keine ewige Verfassungsinvariante.

## 8. Secrets

Die bestehende `security`-Policy bleibt verbindlich: Credentials, Tokens, private Schlüssel und Secret-Plaintext gehören nicht in dieses Repository. Das gilt auch für offline angreifbare Passwort-/Credential-Repräsentationen oder Konfigurationsfelder wie `initialPassword`, `initialHashedPassword`, ungeschützte `hashedPassword`-Werte, Access-Tokens, Netrc-Inhalte, WLAN-PSKs oder LUKS-Keymaterial.

`sops-nix` plus age ist ein bevorzugter 2026-Kandidat für die Aktivierung von Secrets, **aber nicht automatisch für deren Ablage in diesem Repository**.

Bevor `sops-nix` produktiv aktiviert wird, muss der Secret-Quellpfad so festgelegt werden, dass er `security` erfüllt. Bis eine gesonderte Security-Änderung etwas anderes erlaubt, darf dieses Profil keine verschlüsselten Credentials still in `heim-pc` einführen.

Die Recovery-Strategie besitzt mindestens:

- normale Host-/Provisionierungsidentität;
- getrennte hardware-unabhängige Recovery-Identität;
- Offline-Sicherung der Recovery-Identität;
- dokumentierten Rotations- und Wiederherstellungstest.

TPM/FIDO2 darf später als zusätzliche Schutz- oder Komfortschicht hinzukommen, nie als einzige Wiederherstellungsmöglichkeit.

## 9. Supply-Chain-Trust

Vor einem produktiven Executor-Deploy wird ein maschinenlesbarer Trust-Vertrag benötigt.

Er bindet mindestens:

- freigegebene Nixpkgs-/Modulquellen;
- verwendete Binär-Caches;
- Cache-Signaturschlüssel beziehungsweise äquivalente Vertrauensanker;
- Regeln für zusätzliche Substituter;
- OCI-Images über unveränderliche Digests oder gleichwertige verifizierte Identitäten;
- Herkunft eigener Builds/CI-Artefakte.

`latest`, ungebundene Branch-Tarballs oder ungeprüfte Fremdcaches sind keine Produktionsidentität. Impure Evaluation und unhashed Remote-Fetches sind für produktive Control-Plane-Builds nicht zulässig.

Nix-`trusted-users` und vergleichbare Root-äquivalente Vertrauensflächen bleiben minimal; insbesondere wird nicht pauschal `@wheel`, der interaktive Benutzer oder eine Agentenidentität als vertrauenswürdig freigegeben. Änderungen an Substituters, Trust-Keys und Lock-/Release-Set-Identitäten sind reviewpflichtige Supply-Chain-Änderungen.

## 10. Facts-Vertrag

Der NixOS-Build erzeugt eine kleine JSON-kompatible Sollprojektion. Sie enthält mindestens:

- `apiVersion`;
- Host-/Profilidentität;
- gebundene Control-Release-Identität;
- relevante deklarierte Boot-/Kernel-/GPU-/Storage-/Audio-/Runtime-Fähigkeiten;
- Bindung an den gebauten Systemzustand.

Git versioniert den Sollgraphen und die Definition dieser Projektion. `declared-facts` selbst sind daraus abgeleiteter Build-Output beziehungsweise Teil der gebauten Generation und werden **nicht als separat gepflegte aktuelle Soll-/Live-Datei in Git** geführt; Fixtures müssen ausdrücklich als solche markiert sein.

Runtime-Fakten werden separat quellengebunden erhoben. Volatile Runtime-Artefakte folgen dem bestehenden `model` und liegen außerhalb Git mit Quelle, Zeitpunkt, Hashbindung und Frischegrenze.

Agenten vergleichen Soll und Ist. Sie schreiben Runtime-Beobachtungen niemals als neue Konfigurationswahrheit zurück.

## 11. NixOS-Deployment-Pfade

### Automatisierungs-Gate: Managed Nix Builds

Die folgenden `nixos-rebuild`-Schritte beschreiben den **semantischen Executor-Pfad**, erteilen aber noch keine eigenständige Ausführungsautorität für Agenten. Der bestehende kanonische Vertrag `managed-builds` verlangt für automatisierte Operatorläufe einen verwalteten Build-Einstieg; dieser unterstützt derzeit Cargo, Node, Python und Playwright, aber noch keinen Nix/NixOS-Build.

Deshalb gilt fail-closed: **Bis ein reviewter Nix-Buildpfad in `managed-builds` oder ein dort ausdrücklich als gleichwertig gebundener Nachfolgevertrag existiert, dürfen autonome Operatoren `nix build`, `nixos-rebuild build`, `build-vm`, `test`, `boot` oder `switch` nicht direkt als produktiven Host-Deploy ausführen.**

Vor Freigabe automatisierter NixOS-Änderungen muss der Managed-Nix-Buildvertrag mindestens Repository-/Revision-Bindung, Control-Release-Identität, Store-/Cache-Budgets, Prozess-/Lease-Schutz, bounded Receipts, zulässige Privilegien und den Übergang in die nachfolgenden Aktivierungs-Gates definieren. Menschliche Diagnose oder ein separat autorisierter Migrationslauf bleibt davon unterscheidbar und darf nicht als verwalteter Agentenlauf ausgegeben werden.

Der Build-Receipt bindet zusätzlich die **exakte gebaute System-Closure** (`/nix/store/...-nixos-system-*` oder gleichwertige unveränderliche Identität) und den Control-Release-Set-Digest. Jede privilegierte Aktivierungsstufe nimmt ausschließlich diese vorab geprüfte Closure entgegen. Sie darf weder den Git-Checkout neu auswerten noch einen Branch, Lock oder Input erneut auflösen. Eine Source-/Lock-/Release-Set-Abweichung nach dem Build blockiert die Aktivierung statt still eine andere Closure zu erzeugen.

### Wirkungsklassen-Classifier

Die Klasse folgt der **möglichen Wirkung**, nicht Dateiname, Paketname oder behaupteter Absicht. Kann ein Agent die niedrigere Klasse nicht belegen, wird fail-closed in die strengere Klasse eskaliert.

- **Destruktiv:** Änderungen an Partitionstabellen, Dateisystemanlage/-zerstörung, LUKS-Container-/Metadaten-/Keyslot-Wirkung, EFI-/Secure-Boot-Keymaterial oder Firmware-Flash. Diese laufen ausschließlich über den separaten destruktiven Plan.
- **Bootkritisch:** jede nicht-destruktive Änderung, die Kernel, Initrd, Bootloader, frühe Userspace-Pfade, Root-/LUKS-Unlock, frühe Mountabhängigkeiten oder Treiber/Module beeinflussen kann, die vor Erreichen des normalen Userspace benötigt werden. Auch unklare Grenzfälle werden bootkritisch behandelt.
- **Normal:** nur Änderungen, deren Wirkung nachweislich weder destruktiv noch bootkritisch ist.

Eine Änderung an LUKS-/Storage-Konfiguration kann daher bootkritisch sein, während eine tatsächliche Mutation von Container, Partition oder Keyslot destruktiv ist.

### Normale Hoständerung

```text
Entrypoint-spezifische Evaluation/Checks
  (z. B. `nix flake check` und gezieltes `nix eval` beim Flake-Adapter)
-> verwalteter Control-Build
-> Receipt: exakte System-Closure + Control-Release-Set-Digest
-> isolierter/virtueller Test, soweit aussagekräftig
-> closure-gebundene Dry-/Test-Aktivierung ohne Re-Evaluation
-> Runtime-/Hardware-Gates
-> closure-gebundene persistente Aktivierung ohne Re-Evaluation
-> Readback: laufende Closure == freigegebene Closure
```

Es gibt bewusst keinen Pseudobefehl `nix evaluate/check`: Der freigegebene Entrypoint muss die tatsächlich verwendeten `nix eval`-/`nix flake check`-Ziele beziehungsweise einen äquivalenten nicht-Flake-Prüfpfad explizit definieren.

Ein autonomer Agent darf nicht direkt von Quelländerung zu `switch` springen. Die dafür notwendige Root-Wirkung wird über eine enge, allowlist- und receipt-gebundene Aktivierungsschnittstelle vermittelt; ein allgemeiner `sudo`-/Root-Shell-Vertrag oder blanket `NOPASSWD` ist dafür nicht zulässig.

### Bootkritische Änderung

Für Kernel, Initrd, Bootloader, frühe Storage-/LUKS-Pfade oder vergleichbare Änderungen:

```text
Entrypoint-spezifische Evaluation/Checks
-> verwalteter Control-Build
-> Receipt: exakte System-Closure + Control-Release-Set-Digest
-> geeignete isolierte Tests
-> closure-gebundene Next-Boot-Aktivierung ohne Re-Evaluation
-> kontrollierter Reboot
-> Boot-/Hardware-/Runtime-Gates
-> Readback: gebootete Closure == freigegebene Closure
-> bei Fehler: bekannte Generation / Break-glass / Rollback
```

Next-Boot- und persistente Aktivierung werden bewusst nicht als Synonyme behandelt. Beide nehmen ausschließlich die bereits geprüfte, receipte Closure entgegen; ein erneutes `nixos-rebuild boot` oder eine andere Source-/Lock-Re-Evaluation zwischen Build und Bootfreigabe ist für den autonomen Pfad unzulässig.

### Destruktiver Storage-/Firmware-Pfad

Partitionierung, Formatierung, LUKS-Neuanlage, EFI-/Secure-Boot-Key-Änderung und Firmware-Flash laufen **nie** über den normalen Rebuild-Pfad.

Sie benötigen jeweils einen separaten, vorzustandsgebundenen Plan mit Backup-/Recovery-Evidenz, expliziter Zielidentität und Post-Effect-Readback.

## 12. Hardware Acceptance Gates

Buildbarkeit ist nicht Hardwarefunktion. Die nachfolgenden Produktbezeichnungen sind **2026-Acceptance-Anker**, keine Behauptung über das aktuell angeschlossene Inventar. Vor Cutover werden sie aus frischer quellengebundener Runtime-/Hardware-Evidenz bestätigt; Abweichungen erzwingen Profilreview statt stiller Anpassung.

### Gate A — Grafik, GPU, CUDA, CDI

Auf der realen Zielmaschine müssen mindestens funktionieren:

- RTX 4070 Ti SUPER über den freigegebenen NVIDIA-Zweig;
- gewünschte Wayland-Desktop-Session;
- normaler Multi-Monitor-Betrieb;
- CUDA-Compute;
- OCI-GPU-Zugriff über CDI;
- Suspend/Resume mit anschließendem GPU-/Display-/Compute-Readback;
- Rückkehr zu einer bekannten funktionierenden Generation.

Grafischer Vulkan-/GUI-Passthrough ist ein eigenes Gate und nicht automatisch durch einen CUDA-Test bewiesen.

### Gate B — Audio und MIDI

Mit real angeschlossener Hardware:

- PipeWire/WirePlumber stabil;
- MOTU M2 Playback und Capture;
- Browser-/Kommunikations-Playback/Capture;
- Roland FP-30X als tatsächlich nutzbarer MIDI-Pfad;
- erforderliche JACK-Kompatibilität;
- realistische gleichzeitige CPU-/GPU-/Audio-Last ohne unakzeptable Regression;
- Suspend/Resume mit wiederhergestellten Geräten und Routen.

Bluetooth-MIDI ist erst nach realem Test freigegeben. USB-MIDI bleibt ein zulässiger Fallback.

### Gate C — Virtualisierung

KVM-basierte Build-/Integrationstests müssen auf dem Host ausführbar bleiben. Virtuelle Tests ersetzen keine physische GPU-/Audio-/Boot-Prüfung.

### Gate D — Boot, LUKS und Recovery

Auf physischer Hardware müssen mindestens belegt sein:

- UEFI-Boot;
- Initrd und Entschlüsselung;
- korrektes Mounten aller benötigten Zustandsdomänen; im 2026-Btrfs-Profil insbesondere `@data` als eigene Daten-Domäne getrennt von `@persist` und `@containers`;
- manuelle Recovery mit unabhängig verwahrtem Material;
- Boot einer bekannten vorherigen Generation;
- unabhängiger Recovery-Bootpfad;
- Wiederherstellung ohne Grabowski/Bureau/Netzwerk;
- verifizierter Off-host-Restore mindestens eines repräsentativen kritischen Datensatzes;
- Recovery der für das gewählte Verschlüsselungsdesign notwendigen Offline-Metadaten beziehungsweise Header-Sicherung.

### Gate E — Netzwerkidentität und Konnektivität

Die Migration muss den bestehenden `network-identity`-Vertrag ausdrücklich erhalten oder bewusst durch einen gleichwertigen neuen Vertrag ersetzen. Vor permanenter Aktivierung werden mindestens geprüft:

- der erwartete statische Hostname und dessen lokale Auflösung ohne unnötigen DNS-Zugriff;
- die freigegebene Default-Route beziehungsweise bewusst migrierte Schnittstellenidentität;
- mindestens die vertraglich geforderte Ethernet-Linkgeschwindigkeit oder eine explizit akzeptierte neue Netzwerktopologie;
- DNS-Auflösung über den vorgesehenen Heimnetzpfad;
- lokale und externe Konnektivität der für Betrieb und Recovery erforderlichen Ziele;
- kein unbeabsichtigter Verlust der bestehenden fail-closed Netzwerkdiagnostik.

Ein grüner GPU-/Audio-/Boot-Test kompensiert kein degradiertes oder falsch geroutetes Netzwerk.

### Gate F — Datenträger-, Dateisystem- und Stabilitätsbasis

Vor permanentem Cutover werden mindestens dokumentiert und geprüft:

- aktueller NVMe-/SMART-Health-Readback und ein geeigneter Selbsttest, soweit das Gerät ihn unterstützt;
- nach Anlage des Btrfs-Zieldateisystems ein erfolgreicher Scrub beziehungsweise ein gleichwertiger Integritätsreadback ohne unkorrektierbare Fehler;
- eine zur Hardwareänderung passende Speicher-/Systemstabilitätsprüfung, insbesondere wenn UEFI-, RAM-, Kernel- oder Energieeinstellungen geändert wurden;
- der gewählte LUKS-/TPM-/FIDO2-Entsperrpfad gegen ein explizites Threat Model: Komfort-Unlock darf nicht still als Schutz gegen physischen Zugriff ausgegeben werden.

Diese Gates diagnostizieren keine perfekte Hardware; sie verhindern nur, dass eine bereits sichtbare Baseline-Regressionslage als erfolgreiche OS-Migration abgenommen wird.

### Gate G — Lokale Workload-Isolation

Vor Freigabe automatisierter Projekt-/Build-Hooks wird mit einem repräsentativen nicht vertrauenswürdigen Testprozess belegt:

- kein Zugriff auf Secret-Verzeichnisse oder Host-Administrationspfade;
- kein unautorisierter Zugriff auf operatorfähige Loopback-/Unix-Socket-Endpunkte;
- read-only Health-Endpunkte geben nur die ausdrücklich minimierte Information preis;
- Container-/Namespace-Isolation oder Endpoint-Authentisierung bleibt nach Suspend/Restart beziehungsweise Service-Neustart wirksam.

Loopback-Erreichbarkeit allein gilt ausdrücklich nicht als bestandenes Authentisierungs-Gate.

## 13. Desktop und Update-Takt

Der Desktop ist bewusst nur ein Profilparameter. Für 2026 soll genau **eine** primäre Wayland-Desktoplinie stabilisiert werden, statt mehrere Sessions und experimentelle Rices gleichzeitig in den Host aufzunehmen.

NixOS Stable ist die Hostbasis. Einzelne Projekt- oder Userpakete können nur über klar abgegrenzte, bewusst freigegebene Quellen abweichen. Ein kompletter Desktop auf ungebundenem `nixos-unstable` widerspricht dem Ziel eines langweiligen Hosts.

`system.stateVersion` wird bei Installation festgelegt und nicht bei jedem Releaseupgrade reflexartig angehoben.

## 14. Migration bleibt ein separater Vertrag

Dieses Profil legt die Zielarchitektur fest. Es ist **kein Migrationsplan**.

Vor der Migration werden aus frischer Livewahrheit gesondert erstellt:

1. Hardware-/Capability-Inventar;
2. Datenklassifikation und Backup-/Restore-Beleg;
3. Secret-/Recovery-Provisionierung;
4. Storage-Migrationsplan;
5. Hardware-Gate-Plan;
6. Cutover- und Rollbackplan.

Die Architektur wird nicht rückwirkend an eine bequemere Migration angepasst. Umgekehrt darf die Migration keine Invariante umgehen, nur weil der aktuelle Host historisch anders aufgebaut ist.

## Exit-Kriterium dieses Profils

NixOS bleibt Executor, solange es die `system-constitution` insgesamt am besten erfüllt.

Ein Wechsel wird neu bewertet, wenn ein anderer Host nachweislich bessere Gesamtwerte bei Reproduzierbarkeit, Recovery, Hardwarezuverlässigkeit, Trust, Wartbarkeit und Fehlerdomänentrennung bietet. Die Bewertung erfolgt gegen beobachtbare Verträge und Acceptance Gates, nicht gegen NixOS-spezifische Syntaxtreue.
