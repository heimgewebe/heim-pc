---
id: nixos-day1-workload-parity-2026
role: norm
status: canonical
last_reviewed: 2026-10-07
depends_on:
  - system-constitution
  - nixos-executor-2026
  - nixos-dual-os-restplan-2026
verifies_with:
  - tests/test_nixos_system_source.py
---

# NixOS Day-1 Workload Parity 2026

## Zweck und Scope

Dieser Vertrag definiert, welche heute tatsächlich benötigten Heim-PC-Funktionen vor einer **produktiven Rollenübernahme durch NixOS** klassifiziert und nachgewiesen sein müssen.

Er ist **kein Installationsgate für den isolierten Dual-OS-Testpfad**. Eine Installation und ein Testboot auf der separaten Seagate dürfen weiterhin ausschließlich aus den bestehenden Target-, Protected-Disk-, Build-/Attestation-, Boot- und Apply-Gates Autorität erhalten. Ohne erfüllte Day-1-Parität darf ein erfolgreicher Testboot jedoch nicht als produktiver Umzug oder Betriebsparität bezeichnet werden.

## Wahrheitsgrenze

Die kanonischen Runtime-Inventare sind Beobachtungen, keine Norm:

- `runtime/software-inventory.md`
- `runtime/program-inventory-summary.md`

Ihr `observed_at` begrenzt ihre Autorität. Die derzeit eingecheckten Beobachtungen stammen vom 9. Juli 2026 und dürfen deshalb nur historische Kandidaten liefern. Sie dürfen weder heutige Existenz noch heutige Notwendigkeit noch eine Day-1-Freigabe beweisen.

Eine aktuelle Paritätsklassifikation benötigt einen frischen, ausdrücklich an Host `heim-pc` gebundenen Inventarlauf. Ist der Host nicht erreichbar oder fehlt die aktuelle Bindung, bleibt die Paritätsfreigabe fail-closed.

## Klassifikationen

Jeder historische oder aktuell beobachtete Kandidat erhält genau eine Klassifikation:

- `day1-required`: muss vor produktiver Rollenübernahme auf NixOS implementiert und durch Acceptance-Evidenz belegt sein;
- `post-migration`: darf nach der produktiven Rollenübernahme folgen;
- `replaced`: wird bewusst durch einen anderen NixOS-Pfad ersetzt; Ersatz und Acceptance müssen benannt sein;
- `retired`: wird bewusst nicht migriert; die Entscheidung benötigt eine Begründung;
- `unclassified`: noch nicht entschieden und daher blockierend.

Ein Kandidat darf nicht allein deshalb als `day1-required` gelten, weil er im historischen Inventar vorhanden war. Umgekehrt darf ein historischer Kandidat nicht still verschwinden: **jedes einzelne** in den gebundenen historischen Inventaren beobachtete Item muss beim frischen Reconcile entweder als weiterhin vorhanden und klassifiziert oder als explizit `retired`/`replaced` dispositioniert werden. Eine Gruppenklassifikation ersetzt diese Item-Reconciliation nicht.

## Readiness

Day-1-Parität ist erst `ready`, wenn gleichzeitig:

1. ein frischer Inventar-Readback vom Host `heim-pc` gebunden ist;
2. kein Kandidat `unclassified` bleibt;
3. jeder `day1-required`-Kandidat ein konkretes Implementierungsziel besitzt;
4. jeder `day1-required`-Kandidat eine passende Acceptance-Evidenz besitzt;
5. historische Inventare ausschließlich als Seed und nicht als Freigabeautorität verwendet werden.

Der maschinenlesbare Vertrag liegt in `nixos/production/day1-workload-parity-contract-v1.json`.

### Enforcement-Grenze von v1

v1 definiert die normative Readiness- und Reconciliation-Semantik und wird durch Regressionstests gebunden. Ein produktiver Runtime-/Cutover-Consumer ist in diesem PR **noch nicht implementiert**. Diese Abwesenheit ist fail-closed zu interpretieren: Sie darf niemals `ready` erzeugen oder eine produktive Rollenübernahme autorisieren. Bevor ein späterer Pfad `ready` konsumieren darf, muss ein eigener reviewter Consumer exakt diesen Vertrag binden.

## Historische Seed-Gruppen

Die folgenden Gruppen strukturieren nur die Planung; sie sind **keine Vollständigkeitsliste**. Vollständigkeit entsteht durch die item-genaue Reconciliation beider historischen Inventaroutputs gegen den frischen Heim-PC-Readback.

Aus den Beobachtungen vom 9. Juli 2026 werden folgende Prüfdimensionen vorgemerkt:

- Operator-/Transferpfade einschließlich Tailscale/Taildrop;
- lokale OCI-/Utility-Dienste wie Paperless, PostgreSQL, Redis, Backrest, Beszel und Stirling PDF;
- Backup-/Exportpfade;
- Desktop-/Flatpak-Anwendungen;
- Dokument-/OCR-/Medienwerkzeuge;
- Entwicklungs- und Operatorwerkzeuge.

Diese Gruppen sind absichtlich `unclassified`, bis der physische Heim-PC frisch gelesen wurde.

## Architekturentscheidungen

Docker versus Podman, Home-Manager-Integrationsform und die konkrete Paket-/Workload-Verteilung werden aus der frischen Paritätsklassifikation abgeleitet. Der historische Zustand allein entscheidet diese Fragen nicht.

Die Systemverfassung bleibt höher priorisiert. Insbesondere sind Home-Manager-Integrationsform, Disko und die konkrete Container-Runtime austauschbare Implementierungsdetails, solange ihre Invarianten und Acceptance-Verträge erhalten bleiben.

## Nicht-Ziele

Dieser Vertrag:

- aktiviert keinen Dienst;
- installiert keine Pakete;
- verändert keine Storage-, EFI-, LUKS- oder Bootzustände;
- behauptet keine aktuelle Heim-PC-Runtime, solange kein frischer Readback gebunden ist;
- erweitert nicht die Autorität des Produktionsinstallers oder des Day-2-Executors.
