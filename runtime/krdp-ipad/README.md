# iPad-Zugang zum laufenden KDE-Plasma-Konto alex

Stand: 1. November 2026, heim-pc mit NixOS 26.05, Plasma/KWin/KRDP 6.6.6.

## Aktueller Nutzerweg

Die Windows-App auf dem iPad verbindet sich per RDP mit 100.68.88.111:3390 (Tailscale); die RDP-Anmeldung erfolgt als alex. Der Server zeigt einen virtuellen Bildschirm der bestehenden KDE-Wayland-Sitzung mit nativer Auflösung 1168x812 bei Skalierung 1. Er erzeugt keinen separaten Benutzer und nutzt kein Xfce. Gleichzeitige unabhängige Nutzung am lokalen PC und iPad ist nicht vorgesehen.

Die Produktiv-User-Unit app-org.kde.krdpserver.service startet die speziell gepatchte Binärdatei /nix/store/kf94k4j767cm0spfx75y8c910xkjpg4v-krdp-6.6.6/bin/krdpserver mit --address 127.0.0.1 --port 3390 --virtual-monitor 1168x812@1 --plasma. Die User-Drop-in-Quelle liegt hier als krdp-native-override.conf; der GC-Root unter ~/.local/share/krdpserver/krdp-ipad-native-v4 hält die Binärdatei dauerhaft im Store. Der Tailscale-Proxy leitet Port 3390 aus dem Tailnet weiter. Die benötigte gezielte KWin-Berechtigung registriert org.kde.krdpserver-ipad-test.desktop im Benutzer-Application-Verzeichnis, mit exakt derselben gepatchten Binärdatei als Exec.

Die native KWin/KScreen-Ausgabeumschaltung stellt den physischen Monitor nach normaler Trennung und auch nach Stop des KRDP-Servers wieder her. Der bisherige Zusatzdienst krdp-ipad-display-controller.service ist deshalb in der Produktivkonfiguration disabled und inactive. controller.py und seine Unit sind nur als inaktive Rückfallartefakte erhalten. Diese nicht automatisch aktivieren: KWin schaltet den physischen Monitor bereits selbst ab, bevor der Controller seinen Zustand sicher erfassen kann.

## Ursächliche Korrekturen

- patches/krdp-6.6.6-vm-size-v1.patch: fehlende logische Größe beim virtuellen Screencast
- patches/krdp-6.6.6-wl-fixed-pointer-v1.patch: wl_fixed_from_double zur korrekten absoluten Mausposition statt Faktor-256-Fehler
- patches/krdp-6.6.6-fakeinput-auth-v1.patch: gezielte KWin-FakeInput-Authentifizierung
- patches/krdp-6.6.6-virtual-output-pointer-offset-v1.patch: globale Position der virtuellen KWin-Ausgabe berücksichtigen
- patches/krdp-6.6.6-embedded-pointer-v3.patch: genau einen eingebetteten Cursor über den Videostream, zweites RDP-Cursorbild erst nach Streaming-Handshake verbergen

Entscheidend ist auch die native Bildschirmhöhe: 1168x811 darf nicht wieder als H.264/AVC420-Modus verwendet werden. Der FreeRDP-Decoder bekam ein nur 810 Pixel hohes Videoframe, aber einen 811 Pixel hohen Damage-Bereich und verwarf jede Bildaktualisierung. 1168x812 behebt diese Unverträglichkeit ohne Letterbox, Mauskoordinaten-Transformation oder nachträgliche Skalierung. KDE shakecursor ist für alex gezielt deaktiviert; altes kwinrc-Backup lokal erhalten.

## Reproduzierbarer Nix-Build und Persistenz

package.nix leitet KRDP mit sechs gezielten Patches von pkgs.kdePackages.krdp ab; build.sh löst das Nixpkgs des Root-flake.lock auf und baut die gleiche Ableitung. Ausgeführt im Repository:

    ./runtime/krdp-ipad/build.sh

Am 1. November 2026 lieferte der ursprüngliche Fünf-Patch-Build die vorherige v3-Version. Der sechste Patch ergänzt den KDE-Upstream-Authentifizierungsfix. Der aktuelle Build ergibt kf94k4j767cm0spfx75y8c910xkjpg4v; dieser wurde produktiv aktiviert und mit Login und Video geprüft. Die v3-Version und ihre Konfigurationskopien bleiben als Rückfall erhalten. Bei künftigem KWin-Update ist ABI/Version zu prüfen und der neue Store-Pfad sowohl in der User-Unit als auch in der lokalen KDE-Desktopregistrierung anzupassen. Niemals nur die Binärdatei umschalten. Der lokale systemd-Drop-in, Desktop-Eintrag und GC-Root bleiben über normale Benutzeranmeldung, Reboots und NixOS-Profilswitches bestehen; ein echter Reboot-Abnahmetest steht noch aus.

## Nachweise

- grabowski-job-0a7bdd2a4d77: H.264-Client meldet bei 1168x811 einen Damage-Bereich 1168x811 außerhalb des tatsächlichen Frames 1168x810.
- grabowski-job-5b8294ae01be: Isolierter KRDP-6.6.6-Gegenversuch mit 1168x812, 526386 Fensteränderungs- und 18151 Texteingabe-Pixeln, exakter Eingabe und null AVC-Dekodierfehlern.
- grabowski-job-936c401f7d4b: DP-2 ohne Controller nach regulärer Trennung und KRDP-Serverstopp zuverlässig wiederhergestellt.
- grabowski-job-7f3d50cb8812: Produktivserver Port 3390, 488102 geänderte Pixel durch neue KDE-Anwendung, 10933 weitere durch echte Remote-Texteingabe, exakte Zeichenfolge KRDP_PROD_3390_OK, Disconnect- und Reconnect-Restore erfolgreich. Controller war disabled/inactive.
- grabowski-job-2bbfb6313233 sowie grabowski-job-bc6d878c9c90: frühere gezielte Mauskoordinaten- und Anwendungseingabeprüfungen.
- Ein zuvor gekoppeltes iPad erreichte den Tailnet-Port 3390 per TCP. **Nicht** nachgewiesen sind das Videobild und die Touch-Bedienung in der tatsächlichen Windows-App auf dem iPad.

KScreen meldete zuletzt ausschließlich DP-2 mit 2560x1440, Position 0,0 und Skalierung 1 als physischen aktiven Ausgang. DP-1 ist nicht nachgewiesen. Ein grüner CI-Lauf, ein Listener und ein TCP-Connect sind ausdrücklich keine iPad-App-Endabnahme. Ebenfalls offen: Scroll-/Drag-/Eckenabnahme mit dem wirklichen iPad, Produktneustart und erneuter Benutzer-App-Verbindung.

## Rückfall

Beim Verlust der lokalen Bildschirme zuerst laufende RDP-Verbindungen prüfen. Wird kein Preimage gehalten, kann DP-2 über KScreen erneut aktiviert werden; ein verbliebenes Preimage nur nach sichtbarer, tatsächlicher Rückkehr löschen. Die vor der Umstellung vorhandene KRDP-Letterbox-Unit liegt unter ~/.local/share/krdpserver/krdp-unit-before-native-v1.conf und besitzt weiterhin einen GC-Root, ist aber für korrekte Bildgeometrie unzureichend. Der separate XRDP-Xfce-Zugang mit Benutzer ander auf Port 3389 bleibt als Rückfall erhalten. Keine parallele XRDP-X11-Sitzung unter alex starten. Zugangsdaten, TLS-Schlüssel und private Zertifikate sind nicht Teil dieses Repositories.

## Windows-App-Authentifizierung (1. November 2026)

Drei echte iPad-Windows-App-Verbindungsversuche um 12:51 brachen bereits bei CredSSP/NTLM mit SAM-Nachschlagefehler und SEC_E_NO_CREDENTIALS ab, bevor die PAM-Passwortprüfung begann. Linux-Clients mit TLS/PAM hatten zuvor funktioniert.

FreeRDP 3.32.0 aktiviert Extended Security standardmäßig, KRDP 6.6.6 schaltete nur RDP-Security und NLA aus und TLS ein. Die Windows-App bot HYBRID_EX an und geriet dadurch in den SAM-basierten NTLM-Pfad. Die sechste Patchdatei krdp-6.6.6-disable-ext-security-v1.patch überträgt exakt die Upstream-Einzeilenkorrektur von KRDP 6.8.0 (KDE MR 248): FreeRDP_ExtSecurity=false. Klassische unverschlüsselte RDP-Security und NLA bleiben aus, TLS bleibt an. Kein Passwortwechsel, keine SAM-Datenbank und kein zweites Benutzerkonto.


### Produktive Authentifizierungsabnahme

- grabowski-job-cbbb3fcf5b9b: Ein normaler FreeRDP-Client bot SSL, HYBRID und HYBRID_EX an. Gepatchter KRDP handelte TLS aus. Der isolierte Server konnte mangels aktualisierter KWin-Desktop-Berechtigungsregistrierung noch nicht streamen.
- grabowski-job-fcb3da3e8d14: Neue Binärdatei und KWin-Registrierung samt systemd-User-Drop-in gemeinsam aktiviert. Neuer GC-Root krdp-ipad-native-v4. Physischer DP-2 blieb verfügbar.
- grabowski-job-45becbc11dd3: Reale Verbindung auf produktivem Port 3390, Standard-Negotiation SSL|HYBRID|HYBRID_EX zu SSL/TLS, zwei erfolgreiche PAM-Anmeldungen als alex, keine SAM-Fehler, 543585 geänderte Bildpixel bei KDE-Fensteröffnung, 38911 beim Text, exakte Anwendungseingabe, Disconnect/Restore und Reconnect/Restore.
- Rollback-Preimages: ~/.local/share/krdpserver/krdp-native-before-ext-security-20261101.conf und krdp-desktop-before-ext-security-20261101.desktop. Alter GC-Root krdp-ipad-native-v3 bleibt bestehen.
- systemctl --user daemon-reload benötigte auf dem Produktivhost rund 30 Sekunden; kürzere Prüf-Timeouts erzeugten falsche Negativbefunde. Die PID-Argumentliste in /proc/PID/cmdline ist nullbytegetrennt, und der Listener wird erst nach dem Systemd-Service-Start bereit.
- Echte Windows-App auf dem iPad ist nach dem Upstreamfix noch nicht per Nutzerbedienung geprüft. Die Linux-Client-Abnahme ist keine Touch-/Zeiger-Sichtabnahme.
