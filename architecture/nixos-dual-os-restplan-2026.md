# Heim-PC NixOS Dual-OS Restplan 2026

## Ziel

NixOS wird als zweites Betriebssystem ausschließlich auf der separaten 4-TB-Seagate installiert. Pop!_OS auf der 2-TB-WD bleibt vollständig erhalten und bleibt der unabhängige Fallback. Es gibt keinen destruktiven Source-Cutover.

## Festgezurrte Hardware-Rollen

- Geschützt / nicht beschreiben: WD_BLACK SN850X 2000GB, Pop!_OS.
- Einziges destruktives Installationsziel: Seagate ZP4000GP304001 4 TB.
- Kernel-Namen wie `/dev/nvme0n1` und `/dev/nvme1n1` sind Beobachtung, niemals Mutationsautorität.
- Jede destruktive Zieloperation verwendet ausschließlich die private, frisch validierte `/dev/disk/by-id/...`-Identität.
- NixOS erhält eine eigene ESP auf der Seagate. Die Pop!_OS-ESP wird weder geteilt noch beschrieben.
- EFI/NVRAM darf durch den NixOS-Installationslauf nicht verändert werden; OS-Auswahl erfolgt über das Mainboard-UEFI.

## Entfallene Migrationsgates

Für diesen Dual-OS-Pfad sind keine Installationsvoraussetzungen mehr:

1. `HEIMPC_EVIDENCE`-Medium / `RM=1`-Gate;
2. Offline Critical-User-Data Full Inventory;
3. Source-Read-only-Transition für ein Inventar;
4. Preservation Capsules;
5. verpflichtendes Off-host Source-Backup als Installationsgate;
6. source-equivalent Disposable Restore;
7. restored Aggregate Inventory;
8. Source/Restore-Digest-Gleichheit;
9. das daraus abgeleitete Pre-Cutover-Recovery-Readiness-Gate.

Diese Nachweise können unabhängig als Backup-/Recovery-Arbeit weitergeführt werden, erteilen aber keine Installationsautorität.

## Nicht verhandelbare Gates

1. Exakte WD-/Seagate-Identität unmittelbar vor jeder destruktiven Phase.
2. WD-Partitionstabelle, WD-Dateisystemsignaturen und WD-ESP müssen vor/nach Apply identisch sein.
3. Target/Protected-by-id dürfen nicht kollidieren.
4. Seagate muss unmittelbar vor dem Produktionsplan unmounted sein, darf weder Kernel-Holder noch verschachtelte aktive Block-Device-Descendants haben und muss exakt dem privaten, revisionsgebundenen Replacement-Preimage entsprechen; ein separates Vorab-Blanking ist verboten.
5. Eigene Seagate-ESP; Shared ESP verboten.
6. `boot.loader.efi.canTouchEfiVariables = false`; vor Apply muss `BootCurrent` als aktiver Firmware-Eintrag auf die geschützte WD-ESP-PARTUUID und einen dort vorhandenen regulären EFI-Loader zeigen; EFI/NVRAM-Digest vor/nach Apply identisch.
7. Produktionsartefakt muss von `merged-main` stammen und die unabhängige Managed-Build-Attestation bestehen.
8. Versiegelter lokaler Nix-Store und Root-only-Verifikation bleiben Voraussetzung.
9. Private Storage Identity bleibt revisions- und Public-Contract-Digest-gebunden.
10. Firstboot-Credentials werden erst in das verifizierte verschlüsselte Ziel gestaged.
11. Nach Apply: Mapper geschlossen, Seagate-Bootbindung verifiziert, WD unverändert.
12. Erster NixOS-Boot wird über die Firmware-Bootauswahl getestet; anschließend muss Pop!_OS weiterhin unabhängig bootbar bleiben.

## Ausführungsreihenfolge

1. Diese Vertragsänderung testen, reviewen und über Captain nach `main` mergen.
2. Frische Live-Identität von WD und Seagate lesen.
3. Vorhandenen Seagate-Testzustand als privaten Replacement-Preimage aus GPT-GUID, Sektorgröße, Partitionsgrenzen, GUIDs, Labels und Signaturidentitäten binden; kein separater Vorab-Wipe.
4. Für den gemergten Commit einen neuen privaten Storage-Identity-Contract erzeugen; die bisherige revisionsgebundene Datei nicht wiederverwenden.
5. `nixos_production_prepare.py` für exakt den gemergten `main`-Commit ausführen.
6. Unabhängige `nixos-production-build-attest`-Attestation für exakt diesen Kandidaten erzeugen/verifizieren.
7. Produktionsplan effect-frei aus frischer Hardwarewahrheit kompilieren.
8. Plan-Digest, Zielidentität, Target-Quieszenz, Replacement-Preimage und geschützten WD-Firmware-Bootpfad erneut prüfen.
9. Produktions-Apply ausschließlich gegen die Seagate durchführen; `sgdisk --zap-all` bleibt die erste Storage-Wirkung des gehärteten Installers.
10. WD-Fingerprint und EFI/NVRAM unverändert verifizieren.
11. NixOS über Firmware booten und Basissystem/Storage/Firstboot prüfen.
12. Pop!_OS separat booten; erst danach gilt der Dual-OS-Installationspfad als abgeschlossen.

## Stop-Bedingungen

Sofort stoppen ohne Storage-Mutation, wenn Zielidentität, Protected-Identität, Mount-/Holder-/Descendant-Zustand, Attestation, private Identity, WD-Fingerprint, geschützter Firmware-Bootpfad, EFI-Policy oder Plan-Digest nicht exakt stimmen. Nach einer bereits begonnenen Seagate-Mutation wird kein automatischer Source-Rollback behauptet; Pop!_OS bleibt die getrennte, unveränderte Rückfallplattform.
