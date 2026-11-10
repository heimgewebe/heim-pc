# Heim-PC / NixOS: Recovery-, Boot- und 26.11-Umsetzung

Planstand 9. November 2026. Owner: Grabowski (einziger Operator/Writer).
Dies ist ein Plan, kein Nachweis für den aktuell laufenden Stand. Nixer kann
Nix/NixOS lesend evaluieren. Chronik bei Folgearbeiten zuerst gezielt lesen,
danach Git, CI und Runtime frisch an ihren Primärquellen prüfen.

## Ziel und Abnahme

Tägliche Nutzbarkeit, nachgewiesener Rollback, regelmäßige automatische
Wiederherstellungsproben, unabhängige Boot-Generation. 26.11 erst nach
gesicherter Rückfallkette und Kompatibilitätsprüfung. Keine neue Architektur,
wenn der vorhandene NixOS-/systemd-Mechanismus genügt.

## P0: automatische und manuelle NixOS-Rückkehr

- [ ] Pauschalen Versionsvergleich vor dem Switch entfernen. Er verhindert
  die Rückkehr auf ältere, bereits erfolgreiche Generationen. Standard-NixOS-
  Rollback und Day-2-Recovery dürfen nicht von Versionsnummern abhängen.
- [ ] Die bisherigen Closure-Identitäts-, Transaktions- und Profilkontrollen
  sowie die Nix-Lifecycle-GC-Schutzgrenzen beibehalten.
- [ ] Gezielt den Recovery-Fehlerfall testen, Flake-Check, CI und PR prüfen.
- [ ] Nach Integration die aktive Closure und eine nicht destruktive Rückweg-
  probe am Gerät abnehmen. Merge alleine ist keine Produktivabnahme.

## P1: Restic und unabhängiger Restore

- [ ] PR #311 gegen aktuellen main konfliktfrei aktualisieren und mit #343
  koordinieren. Rotation der zehn Restic-Datenpartitionen und konservative
  Retention nur für Host heim-pc-nixos/Tag nixos-seagate übernehmen.
- [ ] Root-Recovery-Probe direkt über systemd auslösen. Der Operator darf
  ihre Ergebnisse lesen, seine Verfügbarkeit ist keine Voraussetzung.
- [ ] Backup-Fenster 07:00/19:30, Restore-Prüfung, Locks, Retention Sonntag
  und notwendige Timeouts kollisionsarm testen.
- [ ] Tatsächlich eine begrenzte Auswahl aus /home/alex und /persist
  wiederherstellen und byteweise vergleichen, Fehlschläge behandeln;
  alte Pop!_OS-Snapshots nicht durch Retention entfernen.
- [ ] Zweites kostenloses unabhängiges Backupziel nur nach Kapazitäts- und
  Restore-Nachweis verwenden. Bis dahin Ausfallrisiko einer USB-Platte nennen.

## P1: EFI, Bootprofile und physischer Kaltstart

- [ ] Aktive, gebootete, als approved und recovery gepinnte Closures gegen
  EFI LoaderEntryDefault, LoaderEntrySysFail und loader.conf abgleichen.
- [ ] Nach einem gesunden, realen Boot approved kontrolliert weiterbewegen,
  bisheriges approved als unabhängige recovery erhalten. Keine Promotion
  allein wegen höherer Versionsnummer oder eines grünen CI-Builds.
- [ ] Nach physischem Neustart Desktop, Anmeldung, SSH, Tailscale, Grabowski,
  Remote-Zugänge und tatsächlich betroffene Clients prüfen.

## P1: NixOS 26.11

- [ ] Flake-Lock und Release-Änderungen, NVIDIA, Plasma/Wayland, Bootloader,
  Netzwerk, Restic und Operator evaluieren, Kandidat separat bauen.
- [ ] Erst nach erfolgreicher P0/P1-Abnahme aktivieren. Eine funktionierende
  26.05-Closure und den unabhängigen Boot-Rückfall erhalten.

## P2: Komplexität senken, Nutzen prüfen

- [ ] Konfliktträchtigen globalen Sourcehash-/Dateianzahl-Test beseitigen;
  gezielte Funktionstests, Lock-Kontrolle und Revision-Identität behalten.
- [ ] Nixer-Neustartverhalten, Ressourcenlimits, SMART, btrfs-Scrub, Microcode
  und Firmware risikogerecht prüfen, nur wirksame Verbesserungen ändern.

## Ausgangsbelege, keine dauerhafte Live-Wahrheit

Am 09.11.2026: GitHub main d63a83ff; PR #311 offen/nicht mergebar;
Root-Check der EFI-Konfiguration noch ausstehend; read-only Readback des
Heim-PC zeigte unterschiedliche approved (31.10.) und recovery (25.10.)
Closures. Restic-Backup erfolgreich, aber kein eigenständiger Probe-Timer
oder vorhandenes proof.json nachgewiesen; Recovery-Refresh mit Exitstatus 1.
Chronik-Full-Search schlug mit chronik_full_search_cli_failed fehl:
keine Aussage über Ereignisfreiheit. Auch neuerer Git-Stand bedeutet
noch keine produktive Aktivierung.

## Abschluss

Abhaken nur mit frischer revisionsgebundener Prüfung. Ein erfolgreicher
Test, PR, Merge oder systemd-Status allein beweist weder physischen Boot
noch Wiederherstellung aus dem Backup. Ergebnisse, Lücken, Risiken und
konkrete Gegenprobe in Chronik (bei erreichbarem Schreibpfad) sichern.
