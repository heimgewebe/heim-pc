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
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# NixOS Executor-Profil 2026

## Status und Grenze

Dieses Dokument konkretisiert die `system-constitution` für den bevorzugten Executor 2026.

**Ziel-Executor:** NixOS Stable 26.05.

Das Profil beschreibt den Sollschnitt für eine spätere NixOS-Migration. Es autorisiert keine Installation, keine Partitionierung, kein Firmware-Update und keinen Eingriff in den produktiven Datenträger.

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

## 5. NVIDIA, CUDA und CDI

Die RTX 4070 Ti SUPER ist Host-Hardware. Der Host besitzt Treiber und Gerätelayer; experimentelle CUDA-/Python-/ML-Stacks gehören nicht global in den Host.

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
        └── @containers
```

Disko beschreibt die produktive Zieltopologie deklarativ.

Die genaue Größe und Position der Partitionen ist keine Verfassungsinvariante und wird erst aus einem frischen Datenträgerinventar und einem gesonderten Migrationsplan festgelegt.

### Root

`@root` wird so vorbereitet, dass ein späterer deterministischer Reset beziehungsweise Impermanence-Light möglich ist.

Ein tmpfs-Root ist **kein** Startziel. Die erste produktive Stufe darf ein persistentes beziehungsweise Btrfs-basiert zurücksetzbares Root verwenden.

Vollständige Impermanence wird erst aktiviert, nachdem die tatsächlich nötigen persistenten Systempfade beobachtet, begründet und getestet sind.

### Nix Store

`@nix` ist persistent und getrennt vom zurücksetzbaren Root. Generationen und Store-Garbage-Collection erhalten eigene Retention-/Budgetregeln; freier Speicher ist kein Grund für ungebundene Löschungen.

### Persist

`@persist` ist eine Whitelist. Typische Kandidaten können Machine-ID, Hostkeys, notwendige Netzwerkidentitäten und ausdrücklich genehmigte Systemzustände sein.

Die Aufnahme eines Pfads ist eine reviewbare Graphänderung. Nach einem Fehler wird nicht reflexartig ein Verzeichnis persistiert.

### Home und Containerdaten

`@home` bleibt persistenter Nutzdatenraum und ist kein Nix-Systemgraph.

`@containers` trennt OCI-Images/-Layer und Workload-Volumes vom Root. CoW bleibt Standard. `nodatacow` wird nicht pauschal auf das Subvolume gesetzt. NOCOW/+C wird nur für gemessene konkrete Write-heavy-Verzeichnisse nach dokumentiertem Trade-off eingesetzt.

## 7. Recovery und Backup

Die produktive Migration darf den bisherigen Recovery-Wert nicht verschlechtern.

Das Zielprofil verlangt zwei verschiedene Recovery-Ebenen:

1. **Host-unabhängiger Boot-/Recovery-Pfad:** nutzbar bei defekter NixOS-Generation oder beschädigtem Root; nicht abhängig von Grabowski, Bureau oder Netzwerk.
2. **Off-host-Datenrestore:** nicht reproduzierbare Daten und benötigtes Recovery-Material müssen von einem anderen physischen oder externen Speicherort wiederherstellbar sein.

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

Die bestehende `security`-Policy bleibt verbindlich: Credentials, Tokens, private Schlüssel und Secret-Plaintext gehören nicht in dieses Repository.

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

`latest`, ungebundene Branch-Tarballs oder ungeprüfte Fremdcaches sind keine Produktionsidentität.

## 10. Facts-Vertrag

Der NixOS-Build erzeugt eine kleine JSON-kompatible Sollprojektion. Sie enthält mindestens:

- `apiVersion`;
- Host-/Profilidentität;
- gebundene Control-Release-Identität;
- relevante deklarierte Boot-/Kernel-/GPU-/Storage-/Audio-/Runtime-Fähigkeiten;
- Bindung an den gebauten Systemzustand.

Diese `declared-facts`-Projektion ist Build-Output beziehungsweise Teil der gebauten Generation, nicht ein nachträglicher Scan des Hosts.

Runtime-Fakten werden separat quellengebunden erhoben. Volatile Runtime-Artefakte folgen dem bestehenden `model` und liegen außerhalb Git mit Quelle, Zeitpunkt, Hashbindung und Frischegrenze.

Agenten vergleichen Soll und Ist. Sie schreiben Runtime-Beobachtungen niemals als neue Konfigurationswahrheit zurück.

## 11. NixOS-Deployment-Pfade

### Normale Hoständerung

```text
nix evaluate/check
-> nixos-rebuild build
-> nixos-rebuild dry-activate
-> build-vm / Integrationstest, wenn aussagekräftig
-> nixos-rebuild test
-> Runtime-/Hardware-Gates
-> nixos-rebuild switch
-> Readback
```

Ein autonomer Agent darf nicht direkt von Quelländerung zu `switch` springen.

### Bootkritische Änderung

Für Kernel, Initrd, Bootloader, frühe Storage-/LUKS-Pfade oder vergleichbare Änderungen:

```text
build
-> geeignete isolierte Tests
-> nixos-rebuild boot
-> kontrollierter Reboot
-> Boot-/Hardware-/Runtime-Gates
-> bei Fehler: bekannte Generation / Break-glass / Rollback
```

`boot` und `switch` werden bewusst nicht als Synonyme behandelt.

### Destruktiver Storage-/Firmware-Pfad

Partitionierung, Formatierung, LUKS-Neuanlage, EFI-/Secure-Boot-Key-Änderung und Firmware-Flash laufen **nie** über den normalen Rebuild-Pfad.

Sie benötigen jeweils einen separaten, vorzustandsgebundenen Plan mit Backup-/Recovery-Evidenz, expliziter Zielidentität und Post-Effect-Readback.

## 12. Hardware Acceptance Gates

Buildbarkeit ist nicht Hardwarefunktion.

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
- korrektes Mounten aller benötigten Zustandsdomänen;
- manuelle Recovery mit unabhängig verwahrtem Material;
- Boot einer bekannten vorherigen Generation;
- unabhängiger Recovery-Bootpfad;
- Wiederherstellung ohne Grabowski/Bureau/Netzwerk;
- verifizierter Off-host-Restore mindestens eines repräsentativen kritischen Datensatzes.

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
