---
id: system-constitution
role: norm
status: canonical
last_reviewed: 2026-09-02
depends_on:
  - model
  - security
  - storage-lifecycle
  - managed-builds
  - operatorium-entry
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# Heim-PC Systemverfassung

## Zweck

Diese Verfassung definiert die langfristigen Systemgrenzen des Heim-PC. Sie ist keine Installationsanleitung und keine Momentaufnahme der laufenden Maschine.

**Strategische Wette:** das Nix-Modell als bevorzugte Beschreibungsschicht für reproduzierbaren Sollzustand.

**Aktueller Executor, Stand 2026:** NixOS. Die konkrete NixOS-Ausprägung steht in `nixos-executor-2026` und ist austauschbar.

Das langfristige Asset ist der versionierte Sollzustand samt Verträgen, Tests, Trust-, Daten- und Recovery-Modell. Nix ist 2026 die bevorzugte Sprache und Auswertungslogik dieses Assets; die Verfassung bindet die Semantik nicht dauerhaft an eine einzelne Distribution oder Entrypoint-Technik.

## Wahrheitsordnung statt globaler Single Source of Truth

Git ist die kanonische Quelle für **deklarierte Sollzustände und normative Verträge**. Git ist ausdrücklich keine globale Livewahrheit.

Für aktuelle Tatsachen gelten weiterhin die vorhandenen Primärquellen aus `model` und `operatorium-entry`:

- Git/GitHub und CI für Revision, Pull Request und technische Checks;
- systemd, Hardware-Readbacks, Logs und Healthchecks für den laufenden Host;
- Grabowski für Operator-Runtime, Ausführung und Leases;
- Bureau für Aufgaben, Claims und Lifecycle-Receipts;
- Systemkatalog für stabile Ökosystemsemantik.

Eine statische Projektion darf keine dieser Autoritäten ersetzen.

## Topologie

```text
                  VERSIONIERTER SOLLZUSTAND
                           Git
                            │
              ┌─────────────┴─────────────┐
              │                           │
        CONTROL PLANE               PROJECT PLANE
              │                           │
       getestetes Release-Set       eigene Pins/Locks/
              │                     OCI-Digests
        ┌─────┴─────┐               │
        │           │          ┌────┼────────┐
      HOST         USER       Rust  Node     AI
        │           │              Workloads
        └─ getrennte Aktivierung ───────┘

                            │
                            ▼
                    RUNTIME / OPERATIONS
                systemd · Hardware · Health
                Grabowski · Bureau · CI
                            │
                     Soll/Ist-Vergleich
                            │
                            ▼
                       DATA / RECOVERY
                Home · Daten · Secrets
                Backups · Recovery-Medien
```

Die Ebenen besitzen unterschiedliche Änderungsraten, Fehlerdomänen und Wahrheitsquellen. Keine Ebene darf still zur zweiten Wahrheit einer anderen werden.

## Die 16 Invarianten

### 1. Vertrag vor Executor

Primäres Asset sind semantische Sollverträge, Konfiguration, Tests und Recovery-Regeln. Der installierte Host ist eine Ausführung davon, nicht deren Quelle.

### 2. Nix ist die strategische Wette, NixOS der aktuelle Executor

NixOS ist 2026 bevorzugter Host, weil es das Nix-Modell auf Systemebene vollständig auswertet. Diese Entscheidung ist bewusst weicher als die Wette auf das Modell.

### 3. Semantische Exit-Klausel

Ein anderer Executor darf NixOS ersetzen, wenn er die geforderten **beobachtbaren Systemverträge** mindestens gleichwertig und insgesamt besser erfüllt: Reproduzierbarkeit, Rollback/Recovery, Hardwareintegration, Trust, Failure-Domain-Trennung, maschinenlesbare Sollprojektion und getestete Betriebswege.

Ein zukünftiger Executor muss NixOS-Module nicht wörtlich auswerten. Bei einem Wechsel wird der Sollvertrag portiert; das Logo oder Dateiformat ist kein Selbstzweck.

### 4. Autorität bleibt quellengebunden

Git definiert Sollzustand. Runtime-Fakten stammen aus Runtime-Primärquellen. Bureau bleibt Taskwahrheit. Grabowski bleibt Operatorwahrheit. CI belegt nur den geprüften Head. Keine Projektion darf daraus eine globale Ersatzwahrheit erzeugen.

### 5. Control Plane ist ein getestetes Release-Set

Host und User teilen nicht nur eine Paketrevision, sondern ein gemeinsam getestetes Control-Release-Set aus den für den Host benötigten Inputs und Vertrauensankern. Die genaue Zusammensetzung ist Executor-spezifisch.

Host und User dürfen getrennt evaluiert und aktiviert werden. Getrennte Failure Domains bedeuten nicht voneinander abweichende, ungeprüfte Control-Paketwelten.

### 6. Project Plane ist autonom

Projekte und Workloads dürfen eigene Pins, Lockfiles, Toolchains, Container-Images und Digests besitzen. Ein Rust-, Node- oder KI-Projekt darf nicht an den Release-Takt des Desktops gekoppelt werden.

### 7. Der Host bleibt klein und langweilig

Der Host enthält nur systemfundamentale Fähigkeiten: Boot, Kernel, Storage-Basis, Hardware, Grafikbasis, Netzwerk, Audio-Basis, Security, fundamentale Dienste und die minimale Ausführungsinfrastruktur für isolierte Workloads.

Schnelllebige Projekt- und KI-Abhängigkeiten dürfen nicht unnötig in den Host leaken.

### 8. Workloads werden nach Fehlerdomäne platziert

Reproduzierbare Projektumgebungen gehören in projektgebundene Entwicklungsumgebungen; opake Vendor-Stacks und geeignete dynamische Anwendungen in isolierte OCI-Workloads. Die konkrete Technik darf sich ändern, die Fehlerdomänentrennung nicht.

GPU- oder Gerätezugriff erhält eine klar definierte Host/Workload-Schnittstelle und eigene Acceptance Gates.

### 9. Storage ist rekonstruierbar, zustandsbewusst und verschlüsselt nach Threat Model

Das Platten- und Mountmodell muss deklarativ oder gleichwertig reproduzierbar beschrieben sein. Systemzustand, Nutzdaten, regenerierbare Daten und Recovery-Material werden explizit getrennt.

Konkrete Werkzeuge, Dateisysteme, Subvolume-Namen und Reset-Verfahren sind Executor-Profil, nicht Verfassung.

### 10. Persistenz wächst nur bewusst

Jeder Pfad, der einen Root-Reset oder eine Rekonstruktion überleben soll, besitzt eine begründete Zuständigkeit. Ein neuer persistenter Systempfad ist eine bewusste Graphänderung mit Review, kein spontaner Rettungsanker nach einem Fehler.

Persistenz darf nicht zu einer versteckten zweiten Installation werden.

### 11. Daten und Recovery sind eigene Assets

Persönliche Daten, Quell- und Arbeitsdaten, Datenbanken, Modelle, Browserzustand, DAW-Projekte, Samples und andere nicht reproduzierbare Nutzdaten sind nicht Teil des Systemgraphen.

Sie besitzen eine eigene Sicherungsstrategie. Mindestens die nicht reproduzierbaren Daten müssen einen verifizierbaren **Off-host-Restore-Pfad** besitzen. Snapshots, Nix-Generationen oder derselbe physische Datenträger gelten nicht allein als Backup.

Zusätzlich existiert ein unabhängiger Recovery-Bootpfad, der nicht vom aktiven Root-Dateisystem abhängt.

### 12. Secrets sind nicht Git-Zustand und müssen recoverbar sein

Secret-Plaintext, private Schlüssel, Tokens und Credentials werden niemals in diesem Repository versioniert. Secret-Provisionierung, Rotation und Recovery sind eigene Verträge und müssen die bestehende `security`-Policy einhalten.

Kein TPM, FIDO2-Token, Mainboard oder einzelnes Hardwaregerät darf die einzige Recovery-Authority sein. Eine hardware-unabhängige Offline-Recovery muss möglich bleiben.

### 13. Supply Chain besitzt einen Trust-Vertrag

Pins allein genügen nicht. Externe Pakete, Binär-Caches, Module, OCI-Images und Build-Artefakte benötigen definierte Herkunfts- und Vertrauensregeln.

Zulässige Quellen, Cache-/Signaturschlüssel, OCI-Digests beziehungsweise gleichwertige unveränderliche Identitäten und CI-/Build-Provenienz werden explizit gebunden. Ein veränderlicher Tag oder ungebundener Download ist keine Produktionsidentität.

### 14. Declared Facts und Runtime Facts bleiben getrennt

Der Build erzeugt eine versionierte maschinenlesbare Sollprojektion, konzeptionell `declared-facts.json`, mit mindestens `apiVersion` und Bindung an den gebauten Sollzustand.

Der laufende Rechner darf separat `runtime-facts.json` oder äquivalente quellengebundene Beobachtungen erzeugen. Runtime-Fakten dienen Healthcheck, Hardwareprüfung, Drift und Diagnose. Sie sind niemals Quelle, aus der der Sollgraph rekonstruiert wird.

```text
Sollgraph -> Build -> Declared Facts -> laufender Host
                                      ↕ Vergleich
                              Runtime Facts
```

Nicht zulässig ist die Umkehrung `Runtime -> neue Wahrheit -> Konfiguration`.

### 15. Änderungen sind nach Wirkungsklasse gestuft

Normale Systemänderungen, bootkritische Änderungen und destruktive Storage-/Firmware-Operationen sind verschiedene Wirkungsklassen.

Ein normaler Agenten-Deploy springt nie direkt von Quelländerung zu permanenter Aktivierung. Er durchläuft Evaluation, Build, geeignete isolierte Tests, temporäre Aktivierung und zielbezogene Runtime-/Hardware-Gates.

Bootkritische Änderungen benötigen Reboot- und Post-Boot-Gates. Destruktive Storage- oder Firmware-Operationen benötigen einen eigenen expliziten Plan mit Backup-/Recovery-Beleg und dürfen niemals als gewöhnlicher System-Switch getarnt werden.

### 16. Recovery darf nicht vom Operator-Ökosystem abhängen

Die Maschine muss im Störfall ohne funktionierendes Grabowski, Bureau, Netzwerk oder laufende Agenten wiederherstellbar sein.

Es existiert ein dokumentierter Break-glass-Pfad für Boot, Entschlüsselung, Zugriff auf Recovery-Material und Rückkehr zu einem bekannten Sollzustand. Automatisierung darf Recovery vereinfachen, aber nicht zu ihrer einzigen Voraussetzung werden.

## Deployment-Policy auf Verfassungsebene

Die konkrete CLI gehört in das Executor-Profil. Die dauerhafte Reihenfolge lautet:

```text
Änderung
  -> Soll-Evaluation
  -> reproduzierbarer Build
  -> isolierte/virtuelle Prüfung, soweit aussagekräftig
  -> temporäre Aktivierung
  -> zielbezogene Runtime- und Hardware-Gates
  -> persistente Aktivierung
  -> Readback gegen Declared Facts
```

Für bootkritische Änderungen:

```text
Build -> nächster Boot -> Reboot -> Post-Boot-Gates -> bestätigen oder Recovery/Rollback
```

Für destruktive Änderungen:

```text
separater Plan -> Off-host-Backup/Restore-Beleg -> unabhängiger Recovery-Pfad
-> exaktes Ziel-Readback -> explizite Wirkung -> Post-Effect-Readback
```

## Trust- und Recovery-Grenze

Die Control Plane darf die laufende Maschine reproduzieren, aber nicht behaupten, Nutzdaten oder Geheimnisse automatisch zu besitzen. Das Daten- und Recovery-System bleibt separat prüfbar.

Ein grüner Build bedeutet daher nicht automatisch:

- funktionierende reale GPU-/Audio-/MIDI-Hardware;
- funktionierende Wiederherstellung nach Datenträgerausfall;
- aktuelle Runtime-Gesundheit;
- Backup-Restore-Fähigkeit;
- sichere Supply Chain außerhalb der gebundenen Inputs.

Diese Eigenschaften benötigen eigene Gates und Belege.

## Nicht-konstitutionelle Implementierungsdetails

Bewusst austauschbar bleiben insbesondere:

- NixOS-Version und konkrete Nix-Implementierung;
- `system.nix`, `flake.nix` oder andere Entrypoints;
- Home-Manager-Integrationsform;
- Disko;
- LUKS-Layout und konkretes Dateisystem;
- Btrfs-Subvolumes, Snapshot-/Reset- oder tmpfs-Verfahren;
- sops-nix, age, TPM oder FIDO2;
- konkreter CDI-Dateiname und Container-Runtime;
- Desktop-Umgebung;
- Verpackung von Ollama, ComfyUI oder anderen KI-Systemen;
- konkrete Backup-Software;
- konkrete Recovery-Medien.

Diese Details dürfen optimiert oder ersetzt werden, solange die Invarianten und Acceptance-Verträge erhalten bleiben.

## Verhältnis zum Repository

`heim-pc` bleibt das kleine versionierte Operatorium-Entrée des lokalen Rechners. Diese Verfassung erweitert diese Rolle um einen normativen Sollvertrag, ohne das Repository zu einer Live-Runtime-Datenbank, einem Home-Spiegel oder einer zweiten Ökosystemkarte zu machen.

Volatile Belege bleiben bei ihren Primärquellen oder als quellengebundene lokale Receipts außerhalb Git. Private Inhalte und Secret-Material bleiben tabu.

## Leitregel

> Der Heim-PC ist kein historisch gewachsener Installationszustand, sondern ein reproduzierbares System mit explizit getrennten Soll-, Runtime-, Workload-, Daten-, Trust- und Recovery-Domänen.

Nix ist die strategische Wette. NixOS ist der aktuelle Executor. Der dauerhafte Vertrag steht über beiden.
