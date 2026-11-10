# Pop!_OS → NixOS: selektive Heimgewebe-Funktionsparität

Stand: 2026-11-07. Auftrag: alle praktisch sinnvollen Alt-Funktionen wieder nutzbar machen oder besser ersetzen. Pop!_OS bleibt unabhängig und unverändert auf der WD Black (`/mnt/wd-black/pop-os`). Nur Grabowski führt Mutationen aus. Nicht als abgeschlossene Produktivabnahme lesen.

## Entscheidungsmethode

Für jede Fähigkeit: (1) Altbestand und echte Daten prüfen, (2) gegen den gegenwärtigen Nutzerweg und eine gepflegte Alternative vergleichen, (3) kleinste nötige Änderung implementieren, (4) echte Datei-/UI-/Audio-Aktion auf installierter NixOS-Revision prüfen. Alte Container, Snap-/Flatpak-Pakete oder systemd-Timer nicht pauschal nachbauen. Pop!_OS-Dateisystem niemals als Schreibziel oder automatisches Backupziel behandeln.

## Vergleich und Umsetzungsstatus

| Alt-Funktion | Auswahl | Begründung / noch erforderliche Abnahme |
|---|---|---|
| WD-Daten (Digitalisierer ~1,4 GiB, CZUR ~927 MiB, Audio ~68 MiB, Taildrop, Snippets) | Nur einzigartige nutzbare Nutzerdaten inventarisieren und selektiv in NixOS-Backupumfang übernehmen | Altplatte bleibt read-only, kein Komplettklon; keine Secrets exportieren; Hash-/Restore-Gegenprobe nötig |
| Pop-Session-Restic/Backrest | Deklarativen NixOS-Restic-Dienst mit externer 4-TB-Platte behalten | PR #311 hat eigenen Writer; keine zweiten Timer. WD-Altbestand fällt nicht automatisch unter NixOS-Backup |
| Taildrop-Empfang | Tailscale `file get --loop --wait --conflict=rename` als Userdienst für alex | Vorhandenen Daemon wiederverwenden, keine neue Netzwerkfreigabe; Empfang von zweitem Gerät und Neustart noch zu testen |
| LAN-Dateiversand | LocalSend als gestartete Desktop-Anwendung bei Bedarf | Einfacher als neue Transfer-App; Dateitransfer und LAN-Erreichbarkeit tatsächlich prüfen; KDE Connect nur bei zusätzlichem Android-KDE-Bedarf |
| Textbausteine: espanso + Snippet Engine Control | Priorität: alten Snippet-Inhalt deduplizieren, Espanso auf Plasma/Wayland im Editor und Browser testen | Bestehendes Klipper deckt Clipboard ab. Keine zweite SEC-Weboberfläche, falls sie nichts verbessert; Wayland-Kompatibilität prüfen |
| Paperless-ngx | Vorläufig NICHT neu deployen | Auf WD ist aktuell nur ein kurzes PDF-Testoriginal mit Testarchiv erkennbar (9.7.2026), ein Alt-Postgres-Verzeichnis existiert. Datenbank/Export zählen und gegen archivierte echte Dokumente prüfen, bevor Dienst oder DB migriert werden |
| OCR, PDF, CZUR | Lokale Nixpkgs-Pakete OCRmyPDF, qpdf, Tesseract, PDF Arranger; Alt-CZUR-Exports selektiv sichten | Keine dauerhafte Stirling-PDF-Web-Instanz ohne echten Zusatznutzen. Eigene PDF teilen/mergen/OCR lesbar prüfen |
| Audio/MOTU/Qobuz | Bestehendes `heimgewebe/audio` und PipeWire als einzige Systemwahrheit | MOTU M2 ist auf NixOS sichtbar. Alt-Mopidy/QBZ nicht unkontrolliert starten; Qobuz-Webplayer bevorzugen, gepflegten Qobuz-Connect-Empfänger nur bei echtem Nutzen; reale Wiedergabe/Recording/iPad prüfen |
| Grabowski Dauersong | Nur bewusst/manuell starten | Alte Arbeit und Dateien erhalten, aber keine Hintergrund-Musik, die ungefragt CPU/Audiogerät belegt |
| DrKonqi/MCE/SMART/Speicherdruck | Bestehende NixOS-Diagnostik und Heim-PC-Dashboard erweitern, wenn tatsächliche Abdeckung fehlt | Keine zweite Beszel-/Log-Strecke, Alarmprobe und SMART-Readback vor Erfolgsmeldung |
| Leitstand/Systemkatalog | Im aktuellen Dashboard und RepoGround fehlende Sichten integrieren | Kein paralleler veralteter Leitstand; E2E-Frage nach Aktion/Fehler/Repo mit tatsächlichem Ergebnis prüfen |
| Ollama/llama.cpp/TinyLlama | Nur on-demand bei messbarem Offline-/Preis-/Qualitätsvorteil | RTX 4070 Ti SUPER vorhanden, aber Agentenrouter bereits aktiv. Keine dauerhafte Modellinstanz ohne Probe |
| iCloud Drive | Webzugriff + Taildrop/LocalSend statt fragiler Dauer-rclone-Mount | Alter iCloud-rclone-Remote war noch nie erfolgreich authentifiziert; kein verlorener aktiver Sync |
| Sunshine/Moonlight | Vorhandene KRDP/RustDesk-Weg zuerst wirklich mit iPad abnehmen | PR #302/#331 in eigener Lane. Ergänzung nur bei nachgewiesener Low-Latency-Vorteil |
| Sonstige alte Flatpaks/Container (Mattermost, UniFi, OBS, Obsidian etc.) | Nutzung und aktuellen Host prüfen, nur belegte Funktionen wieder anbieten | Kein automatisches Duplizieren von Diensten, die inzwischen anderswo laufen |

## Reihenfolge / Abnahme

1. P0: Alt-Daten-Bestandsaufnahme und aktuelle Backups sauber abgleichen; Paperless-Datenbank nicht im laufenden Zustand kopieren. Daten können auf WD bleiben, bis ihre Sicherung geklärt ist.
2. P1: Taildrop-Empfang; LocalSend; OCR/PDF/CZUR. Echte Datei iPad/Telefon ↔ Heim-PC, PDF-OCR und Merge testen.
3. P1: Snippet-Weg mit alten Kürzeln und Wayland-Kompatibilität. Bei schlechter Funktion den kleinsten stabilen KDE-Weg statt einer neuen großen Anwendung verwenden.
4. P1: Audio-Repository integrieren. Qobuz-Wiedergabe und MOTU-Signalweg vor Aufnahmen. iPad-Read-only-Bridge erst danach.
5. P2: Fehlende Diagnostik und Dashboard-Sichten, gegebenenfalls lokale KI. Nur bei tatsächlichem Nutzerwert.
6. P3: Optionen und Alt-Katalog abschließen. Jede als übernommen/ersetzt/entbehrlich/offen samt Nachweis klassifizieren. Neustart-/Restic-Restore-Probe nach tatsächlich installiertem Release.

## Aktuelle Isolations- und Fehlergrenzen

Basis: `heimgewebe/heim-pc` GitHub main vom 7.11.2026 (`ab0c0fe706fb13ee49f3c4cd2413127a2a6993d0`), eigenständige Lane `fd1e865f7bf8ba304d43f31b3ecd65fc`. Andere laufende PRs (u. a. 311 Restic, 331 RustDesk, 333 Grabowski, 302 KRDP) nicht ändern oder überlagern. Keine produktive NixOS-Umschaltung/Reboot und kein Zugriff auf WD-ESP ohne getrennte Abnahme. Jeder Merge und jeder System-Deploy braucht danach einen frischen eigenen Livebeleg.

Altdaten-Startbelege: `/mnt/wd-black/pop-os/home/alex`; Dateisystem schreibgeschützt; Paperless-Testoriginal `media/documents/originals/0000001.pdf`; aktuelles NixOS-Home `/home/alex`; Backupumfang laut `nixos/system/modules/restic-seagate-backup.nix`.
