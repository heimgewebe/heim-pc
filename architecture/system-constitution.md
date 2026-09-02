---
id: system-constitution
role: norm
status: canonical
last_reviewed: 2026-09-02
depends_on:
  - model
  - security
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# Heim-PC Host-Verfassung

## Zweck

Diese Verfassung definiert ausschließlich die langfristigen **host-lokalen** Soll-, Zustands-, Trust-, Daten- und Recovery-Grenzen des Heim-PC. Sie ist keine Installationsanleitung, keine Momentaufnahme der laufenden Maschine und keine zweite Ökosystemkarte.

**Strategische Wette für den Host:** das Nix-Modell als bevorzugte Beschreibungsschicht für reproduzierbaren Sollzustand.

**Ausgewählter Ziel-Executor, Stand 2026:** NixOS. Der laufende Host bleibt bis zum belegten Cutover eine separate Runtime-Wahrheit. Die konkrete NixOS-Ausprägung steht in `nixos-executor-2026` und ist austauschbar.

Das langfristige Host-Asset ist der versionierte Sollzustand samt lokalen Verträgen, Tests, Trust-, Daten- und Recovery-Modell. Nix ist 2026 die bevorzugte Sprache und Auswertungslogik dieses Assets; die Verfassung bindet die Host-Semantik nicht dauerhaft an eine einzelne Distribution oder Entrypoint-Technik.

## Autoritätsgrenze

Diese Datei **definiert keine systemweiten Zwecke, Beziehungen oder Wahrheitszuständigkeiten**. Dafür bleibt der Systemkatalog kanonisch. `heim-pc` konsumiert diese Zuordnungen nur und darf sie nicht lokal neu erfinden.

Innerhalb dieses Repositories ist Git die kanonische Quelle für **deklarierte host-lokale Sollzustände und normative Host-Verträge**. Git ist ausdrücklich keine globale oder laufende Livewahrheit. Aktuelle Tatsachen werden weiterhin aus den in `model` und dem Systemkatalog ausgewiesenen Primärquellen gelesen.

Eine statische Projektion dieser Host-Verfassung darf keine externe Autorität ersetzen oder neue Ökosystemautorität begründen.

### Konflikt- und Zuständigkeitsregel

Diese Verfassung baut nur auf den langfristigen Basisschichten auf:

- `model` definiert die Trennung von statischem Soll-/Orientierungszustand, quellengebundenen Betriebsartefakten und Live-Primärquellen;
- `security` definiert Daten-, Disclosure-, Endpoint- und Secret-Grenzen;
- der Systemkatalog bleibt kanonisch für systemweite Zwecke, Beziehungen und Wahrheitszuständigkeiten.

Operative Verträge für Entrée, Storage-Lifecycle, Build-Lifecycle oder andere heutige Implementierungsflächen bleiben eigenständig und dürfen sich weiterentwickeln, ohne dadurch eine Verfassungsreview zu erzwingen. Sie und jedes Executor-Profil müssen die Verfassung respektieren; die Verfassung hängt nicht von ihrer konkreten heutigen Ausprägung ab.

Bei einer Überschneidung gilt ohne einen ausdrücklich reviewten engeren Vertrag die **strengere Sicherheits- und Nichtmutationsregel**. Ein Executor-Profil darf die Basisschichten nur konkretisieren, nicht lockern.

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
        ┌─────┴─────┐          ┌────┼────────┐
        │           │          │    │        │
      HOST         USER       Rust  Node     AI
        │           │          └────┴────────┘
        └── getrennte Aktivierung     │
                                      └── eigene Deploy-Zyklen

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

Entrypoints, Adapter und alternative Auswertungswege dürfen denselben Sollgraphen projizieren, aber **keine zweite fachliche Konfiguration oder parallele Sollwahrheit** entwickeln. Ein neuer Entrypoint ist eine andere Sicht auf denselben Vertrag, kein Fork der Host-Semantik.

### 2. Nix ist die strategische Wette, NixOS der ausgewählte Ziel-Executor

NixOS ist 2026 der ausgewählte Ziel-Host, weil es das Nix-Modell auf Systemebene vollständig auswertet. Bis zum erfolgreich abgenommenen Cutover beschreibt das keinen aktuellen Runtime-Zustand. Diese Entscheidung ist bewusst weicher als die Wette auf das Modell.

### 3. Semantische Exit-Klausel

Ein anderer Executor darf NixOS ersetzen, wenn er die geforderten **beobachtbaren Systemverträge** mindestens gleichwertig und insgesamt besser erfüllt: Reproduzierbarkeit, Rollback/Recovery, Hardwareintegration, Trust, Failure-Domain-Trennung, maschinenlesbare Sollprojektion und getestete Betriebswege.

Ein zukünftiger Executor muss NixOS-Module nicht wörtlich auswerten. Bei einem Wechsel wird der Sollvertrag portiert; das Logo oder Dateiformat ist kein Selbstzweck.

### 4. Externe Autorität wird konsumiert, nicht neu definiert

Diese Host-Verfassung besitzt keine Ökosystem-Wahrheitsdomäne. Sie bindet nur, dass host-lokaler Sollzustand nicht mit beobachtetem Runtime-Zustand vermischt werden darf. Welche externen Systeme für Git-, CI-, Task-, Operator- oder Ökosystemzustand autoritativ sind, wird aus dem Systemkatalog und den dort gebundenen Primärquellen übernommen.

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

Workload-Code erhält durch bloße Ausführung auf dem Host keine implizite Host-Administrations- oder Secret-Autorität. Das gilt ausdrücklich auch für Build- und Install-Hooks wie `build.rs`, Paketmanager-Lifecycle-Skripte oder vergleichbare fremde Buildbackends.

### 9. Storage ist rekonstruierbar, zustandsbewusst und verschlüsselt nach Threat Model

Das Platten- und Mountmodell muss deklarativ oder gleichwertig reproduzierbar beschrieben sein. Systemzustand, Nutzdaten, regenerierbare Daten und Recovery-Material werden explizit getrennt.

Konkrete Werkzeuge, Dateisysteme, Subvolume-Namen und Reset-Verfahren sind Executor-Profil, nicht Verfassung.

### 10. Persistenz wächst nur bewusst

Jeder Pfad, der einen Root-Reset oder eine Rekonstruktion überleben soll, besitzt eine begründete Zuständigkeit. Ein neuer persistenter Systempfad ist eine bewusste Graphänderung mit Review, kein spontaner Rettungsanker nach einem Fehler.

Persistenz darf nicht zu einer versteckten zweiten Installation werden.

### 11. Daten und Recovery sind eigene Assets

Persönliche Daten, Quell- und Arbeitsdaten, Datenbanken, Modelle, Browserzustand, DAW-Projekte, Samples und andere nicht reproduzierbare Nutzdaten sind nicht Teil des Systemgraphen.

Zustandsbehaftete Service- und Workload-Daten bilden dabei eine eigene **Daten-Domäne**. Sie dürfen weder still in Systempersistenz noch in regenerierbare Container-/Cache-Domänen einsickern; konkrete Mount- oder Subvolume-Namen bleiben Executor-Detail.

Sie besitzen eine eigene Sicherungsstrategie. Mindestens die nicht reproduzierbaren Daten müssen einen verifizierbaren **Off-host-Restore-Pfad** besitzen. Snapshots, Nix-Generationen oder derselbe physische Datenträger gelten nicht allein als Backup.

Zusätzlich existiert ein unabhängiger Recovery-Bootpfad, der nicht vom aktiven Root-Dateisystem abhängt.

### 12. Secrets sind nicht Git-Zustand und müssen recoverbar sein

Secret-Plaintext, private Schlüssel, Tokens und Credentials werden niemals in diesem Repository versioniert. Secret-Provisionierung, Rotation und Recovery sind eigene Verträge und müssen die bestehende `security`-Policy einhalten.

Kein TPM, FIDO2-Token, Mainboard oder einzelnes Hardwaregerät darf die einzige Recovery-Authority sein. Eine hardware-unabhängige Offline-Recovery muss möglich bleiben.

### 13. Supply Chain besitzt einen Trust-Vertrag

Pins allein genügen nicht. Externe Pakete, Binär-Caches, Module, OCI-Images und Build-Artefakte benötigen definierte Herkunfts- und Vertrauensregeln.

Zulässige Quellen, Cache-/Signaturschlüssel, OCI-Digests beziehungsweise gleichwertige unveränderliche Identitäten und CI-/Build-Provenienz werden explizit gebunden. Ein veränderlicher Tag oder ungebundener Download ist keine Produktionsidentität.

### 14. Declared Facts und Runtime Facts bleiben getrennt

Git trägt den deklarativen Sollgraphen sowie die Generator-/Schema-Definition für dessen maschinenlesbare Projektion. Der Build leitet daraus deterministisch `declared-facts` ab und bindet sie an den konkret gebauten Sollzustand. `declared-facts` sind damit **Build-Artefakt beziehungsweise Teil der Generation und keine separat gepflegte Live- oder Soll-Datei in Git**.

Die Sollprojektion enthält mindestens `apiVersion` und die Bindung an den gebauten Sollzustand. Der laufende Rechner darf separat `runtime-facts.json` oder äquivalente quellengebundene Beobachtungen erzeugen. Runtime-Fakten dienen Healthcheck, Hardwareprüfung, Drift und Diagnose. Sie sind niemals Quelle, aus der der Sollgraph rekonstruiert wird.

```text
Sollgraph -> Build -> Declared Facts -> laufender Host
                                      ↕ Vergleich
                              Runtime Facts
```

Nicht zulässig ist die Umkehrung `Runtime -> neue Wahrheit -> Konfiguration`.

### 15. Änderungen sind nach Wirkungsklasse gestuft

Normale Systemänderungen, bootkritische Änderungen und destruktive Storage-/Firmware-Operationen sind verschiedene Wirkungsklassen.

Ein normaler Agenten-Deploy springt nie direkt von Quelländerung zu permanenter Aktivierung. Er durchläuft Evaluation, Build, geeignete isolierte Tests, temporäre Aktivierung und zielbezogene Runtime-/Hardware-Gates.

Privilegierte Aktivierung besitzt eine **enge, allowlist- und receipt-gebundene Wirkungsschnittstelle**. Ein allgemeiner Root-Shell-Zugang, pauschales `NOPASSWD` oder eine gleichwertige ungebundene Eskalation ist kein zulässiger Agenten-Deploy-Vertrag.

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

Diese Verfassung besitzt ausschließlich den **host-lokalen** Sollvertrag des Rechners. Sie erweitert keine Ökosystemautorität und legt die übrige Repository-Rolle nicht neu fest. Systemweite Zwecke, stabile Beziehungen, Wahrheitszuständigkeiten und Einstiegspunkte bleiben im Systemkatalog; diese Datei darf davon höchstens referenzieren oder lokale Konsequenzen ableiten.

Volatile Belege bleiben bei ihren Primärquellen oder als quellengebundene lokale Receipts außerhalb Git. Private Inhalte und Secret-Material bleiben tabu.

## Leitregel

> Der Heim-PC ist kein historisch gewachsener Installationszustand, sondern ein reproduzierbares System mit explizit getrennten Soll-, Runtime-, Workload-, Daten-, Trust- und Recovery-Domänen.

Nix ist die strategische Wette. NixOS ist der ausgewählte Ziel-Executor; welcher Executor tatsächlich läuft, wird ausschließlich aus frischer Runtime-Wahrheit bestimmt. Der dauerhafte Vertrag steht über beiden.
