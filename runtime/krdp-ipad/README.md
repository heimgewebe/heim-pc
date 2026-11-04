# iPad-Zugang zum laufenden KDE-Plasma-Konto alex

## Aktueller produktiver Stand – 4. November 2026

**Verbindlicher Nutzerweg:** Microsoft Windows App auf dem iPad → `heim-pc.tail6dbb90.ts.net:3391` (alternativ `100.68.88.111:3391`) → Tailscale Serve → KRDP `127.0.0.1:3390` → bestehende KDE-Wayland-Sitzung von `alex`. Extern `:3390` ist dagegen XRDP und **nicht** der geteilte KDE-Desktop. Der Host läuft auf der tatsächlich gebooteten NixOS-Gen46 mit KDE Plasma/KWin 6.6.6.

**Aktueller Betriebsmodus:** gepinnter KRDP 6.7.0 mit elf Quellpatches, einschließlich physischer Ausgabebreite (`screen->size()`) und korrektem Zeiger-Monitorursprung (`QScreen::geometry()`); `--monitor 0 --plasma` statt virtuellem 1168×812-Monitor. Exakter mit `./runtime/krdp-ipad/build.sh` reproduzierter Storepfad: `/nix/store/rldcrsfdhgm20xqnpra4c3g7h11zqj6d-krdp-6.7.0`. Die Benutzer-Unit `app-org.kde.krdpserver.service` und die KWin-Anwendungsberechtigung `org.kde.krdpserver-ipad-test.desktop` müssen **beide exakt diesen** `bin/krdpserver` verwenden. `KRDP_EMBED_CURSOR=1` und `KRDP_RDPEI_TOUCH=1` bleiben gesetzt. Ein systemd-Benutzer-Drop-in und die Desktop-Registrierung liegen lokal unter `~/.config/systemd/user/app-org.kde.krdpserver.service.d/override.conf` und `~/.local/share/applications/org.kde.krdpserver-ipad-test.desktop`. Die beiden Dateien dieses Verzeichnisses sind die zugehörigen wiederherstellbaren Sourcevorlagen, nicht der Nachweis eines bereits vollständig deklarativen NixOS-Aktivierungswegs.

**Nachweise:** Der zusätzliche Pointerpatch wurde separat mit authentifizierten RDP-Eingaben auf DP-1 (3840×2160, Skalierung 1,7) und DP-2 (2560×1440, Skalierung 1, Offset 2259) jeweils an fünf Positionen exakt gegen KWin gemessen. Der komplette Nix-Build des PR #302 ergibt denselben Storepfad wie der gestartete Produktivdienst. Am 4.11. um 07:12 Uhr authentifizierte eine RDP-Verbindung und öffnete RDPEI, aber das Journal meldete wiederholt `PipeWire frame did not contain usable image data`; der Clienttransport brach um 07:17 Uhr ab. **Ein fehlerfreies natives iPad-Bild sowie Maus, Fingertipps, Ziehen, Scrollen, Tastatur und Reconnect sind weiterhin nicht abgenommen.** Die Juno-Python-Umgebung kann die iPad-Windows-App nicht selbst bedienen.

**Monitore und Rückfall:** Bei der aktuellen Live-Abfrage meldete der DRM-Kernel DP-2 als verbunden und DP-1 als *disconnected*. KScreen zeigte DP-2 allein bei 2560×1440, Skalierung 1, Position 0,0. Das ist kein Beleg, dass die frühere Zweimonitor-Anordnung nach der aktuellen Verbindung wiederhergestellt wurde; sie darf auch nicht ohne physischen Anschlussstatus erzwungen werden. Der optionale `krdp-ipad-display-controller.service` bleibt deaktiviert. Vor Serverwechsel aktive RDP-Verbindungen ausschließen; bei einer Regression das lokal gesicherte vorige User-Drop-in und den KWin-Desktop-Eintrag zusammen zurückstellen. Gen46-Boot und Gen38-Recovery unverändert lassen.

## Historischer Entwicklungs- und Testverlauf

Die nachfolgenden Angaben vom 1.–3. November dokumentieren frühere virtuelle Monitormodi und Binärrevisionen; sie gelten **nicht** als aktuelle Produktiv-Anweisung. Maßgeblich sind die eben genannten Einstellungen und die aktuelle Sourcevorlage.

Stand: 1. November 2026, heim-pc mit NixOS 26.05, Plasma/KWin 6.6.6 mit unabhängig gepinntem KRDP 6.7.0 (Progressive Encoding).

## Aktueller Nutzerweg

Die Windows-App auf dem iPad verbindet sich per RDP mit 100.68.88.111:3391 (Tailscale, **KRDP**); die RDP-Anmeldung erfolgt als alex. Der Server zeigt einen virtuellen Bildschirm der bestehenden KDE-Wayland-Sitzung mit nativer Auflösung 1168x812 bei Skalierung 1. Er erzeugt keinen separaten Benutzer und nutzt kein Xfce. Gleichzeitige unabhängige Nutzung am lokalen PC und iPad ist nicht vorgesehen.

Die Produktiv-User-Unit app-org.kde.krdpserver.service startet die speziell gepatchte Binärdatei /nix/store/7rmym4cqlr327y2yij2fjbnd5dzx5zr4-krdp-6.7.0/bin/krdpserver mit --address 127.0.0.1 --port 3390 --virtual-monitor 1168x812@1 --plasma. Die User-Drop-in-Quelle liegt hier als krdp-native-override.conf; der GC-Root unter ~/.local/share/krdpserver/krdp-ipad-native-v5 hält die Binärdatei dauerhaft im Store. Stand 03.11.2026: Tailscale Serve leitet den **externen Port 3391** auf den **internen KRDP-Port 127.0.0.1:3390**. Der externe Port 3390 führt stattdessen zum XRDP-Rückfall auf 127.0.0.1:3389. Vor der Nutzerabnahme `tailscale serve status` frisch prüfen. Die benötigte gezielte KWin-Berechtigung registriert org.kde.krdpserver-ipad-test.desktop im Benutzer-Application-Verzeichnis, mit exakt derselben gepatchten Binärdatei als Exec. Ein systemd-ExecStartPre aktualisiert den KService-Cache bei jedem Dienststart, damit die private Screencast-Schnittstelle rechtzeitig freigegeben wird.

Die native KWin/KScreen-Ausgabeumschaltung stellt den physischen Monitor nach normaler Trennung und auch nach Stop des KRDP-Servers wieder her. Der bisherige Zusatzdienst krdp-ipad-display-controller.service ist deshalb in der Produktivkonfiguration disabled und inactive. controller.py und seine Unit sind nur als inaktive Rückfallartefakte erhalten. Diese nicht automatisch aktivieren: KWin schaltet den physischen Monitor bereits selbst ab, bevor der Controller seinen Zustand sicher erfassen kann.

## Ursächliche Korrekturen

- patches/krdp-6.6.6-vm-size-v1.patch: fehlende logische Größe beim virtuellen Screencast
- patches/krdp-6.6.6-wl-fixed-pointer-v1.patch: wl_fixed_from_double zur korrekten absoluten Mausposition statt Faktor-256-Fehler
- patches/krdp-6.6.6-fakeinput-auth-v1.patch: gezielte KWin-FakeInput-Authentifizierung
- patches/krdp-6.6.6-virtual-output-pointer-offset-v1.patch: globale Position der virtuellen KWin-Ausgabe berücksichtigen
- patches/krdp-6.6.6-embedded-pointer-v3.patch: genau einen eingebetteten Cursor über den Videostream, zweites RDP-Cursorbild erst nach Streaming-Handshake verbergen

Entscheidend ist auch die native Bildschirmhöhe: 1168x811 darf nicht wieder als H.264/AVC420-Modus verwendet werden. Der FreeRDP-Decoder bekam ein nur 810 Pixel hohes Videoframe, aber einen 811 Pixel hohen Damage-Bereich und verwarf jede Bildaktualisierung. 1168x812 behebt diese Unverträglichkeit ohne Letterbox, Mauskoordinaten-Transformation oder nachträgliche Skalierung. KDE shakecursor ist für alex gezielt deaktiviert; altes kwinrc-Backup lokal erhalten.

## Reproduzierbarer Nix-Build und Persistenz

package.nix baut KRDP 6.7.0 vom SHA256-gepinnten KDE-Quellcommit mit sieben Korrekturpatches auf derselben KWin-/Nixpkgs-6.6-Basis; build.sh löst das Nixpkgs des Root-flake.lock auf und baut die gleiche Ableitung. Ausgeführt im Repository:

    ./runtime/krdp-ipad/build.sh

Am 1. November 2026 lieferte der ursprüngliche Fünf-Patch-Build die vorherige v3-Version. Der sechste Patch ergänzt den KDE-Upstream-Authentifizierungsfix. Der frühere v4-Build mit sechs Patches behob NLA/TLS und H.264-Grundfehler, konnte aber keine iPad-Clientverbindung ohne AVC420 übertragen. Der aktuelle sieben-Patch-Build ergibt die v5-Binärdatei 7rmym4cqlr327y2yij2fjbnd5dzx5zr4-krdp-6.7.0. Alte v4/v3-Konfigurationen und ihre Nix-GC-Roots bleiben als Rückfall erhalten. Bei künftigem KWin-Update ist ABI/Version zu prüfen und der neue Store-Pfad sowohl in der User-Unit als auch in der lokalen KDE-Desktopregistrierung anzupassen. Niemals nur die Binärdatei umschalten. Der lokale systemd-Drop-in, Desktop-Eintrag und GC-Root bleiben über normale Benutzeranmeldung, Reboots und NixOS-Profilswitches bestehen; ein echter Reboot-Abnahmetest steht noch aus.

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


## Native Progressive-Grafik und Windows-/iPad-Kompatibilität

KRDP 6.6.6 ist auf RDPGFX H.264/AVC420 beschränkt. Nach erfolgreicher PAM-Anmeldung scheiterte die echte iPad-Windows-App am 1. November 2026 (13:27 und 13:58 Uhr) mit ERRINFO_GRAPHICS_SUBSYSTEM_FAILED. Ihre Grafik-Capabilities enthielten kein kompatibles H.264/AVC420-Profil. Die Ursache ist vom vorherigen NLA-/SAM-Anmeldefehler unabhängig.

Der gepinnte KRDP-6.7.0-Quellstand enthält Progressive Encoding für RDP-Clients ohne AVC420. package.nix fixiert den offiziellen KDE-Commit b1a49644aed95132ac0d2eee19780040c061fdaa und dessen SHA256, statt flüchtige /run-Quellen zu referenzieren. package-krdp-6.6.6.nix hält die vorherige Quelle als Rückfall vor. Zusätzlich zu den vier weiter passenden 6.6-Patches werden drei eng abgegrenzte Fixes verwendet:

- krdp-6.7.0-virtual-output-pointer-offset-v1.patch: globaler KWin-Ausgabeoffset für präzise RDP-Mauspositionen.
- krdp-6.7.0-embedded-pointer-v1.patch: Cursor im Videostream und zweite RDP-Cursordarstellung erst nach vollständig initialisierter Verbindung verstecken.
- krdp-6.7.0-close-videostream-on-qt-thread-v1.patch: PipeWire-Stream auf dem zuständigen Qt-Thread schließen. Behebt die Fehlermeldung pw_stream_set_active called from wrong context und eine nach Verbindungsende hängenbleibende virtuelle Ausgabe.

**Isolierte E2E-Belege:** grabowski-job-17dee2a7079f (Progressive-Grafik und echte KDE-Textänderung), grabowski-job-26ab282b1dab (DP-2 kehrt nach normalem Disconnect binnen unter einer Sekunde zurück), grabowski-job-357c92300f38 (beide Grafikmodi mit realen Anwendungen und Wiederherstellung erfolgreich; eine überstrenge zusätzliche Log-Debug-Assertion markierte nur den Gesamtjob fälschlich rot), grabowski-job-b0ffce004038 (exakt aus dem Repository gepinnter Build mit 444433 Fenster- und 3337 Text-Pixeln, korrekter Eingabe und DP-2-Rückkehr nach KRDP-Serverstopp). Die neue Binärdatei besitzt einen per nix-store --add-root registrierten GC-Root unter ~/.local/share/krdpserver/krdp-ipad-native-v5.

**Windows-Rechner fotolabor:** Das bereits vorhandene RDP-Profil unter C:\Users\mohrc\Desktop\Fotolabor-Heim-PC-KRDP.rdp verwendete historisch Tailscale-MagicDNS heim-pc.tail6dbb90.ts.net:3390, Nutzer alex, 1168x812 Fenstermodus, keine hartkodierten Zugangsdaten. Aktuell führt dieser **externe** Port zu XRDP; für den KDE/KRDP-Weg ist das Profil vor einem neuen echten MSTSC-Test auf `heim-pc.tail6dbb90.ts.net:3391` zu ändern. Diese Dokumentationskorrektur ändert die Windows-Datei auf fotolabor nicht. Das Original wurde unter %LOCALAPPDATA%\Heim-PC\rdp-backups\Fotolabor-Heim-PC-KRDP-before-1168x812.rdp gesichert. Die Windows-MSTSC-Verbindung erreichte den Server, aber eine PAM-Prüfung schlug am 1. November 2026 um 13:57 Uhr fehl. Diese Clientauthentifizierung ist gesondert real zu verifizieren.

**Weiter ausdrücklich offen:** Das konkrete iPad-Windows-App-Bild, Touch, Scrollen, Cursorgröße und Drag-Verhalten nach dem produktiven Progressive-Switch; außerdem Host-Reboot und Wiederanmeldung. Headless-FreeRDP-Praxistests ersetzen keine echte iPad-App-Endabnahme. Auf dem Host wurde zuletzt nur DP-2 von KScreen gesehen; DP-1 ist nicht als wiederhergestellt nachgewiesen.



## Produktivabnahme mit KRDP 6.7.0 – 1. November 2026

- grabowski-job-23f254753708: gepinnter sieben-Patch-Build 7rmym4cqlr327y2yij2fjbnd5dzx5zr4 als neuer aktiver KRDP-Userdienst auf Port 3390 gestartet. Desktop-Berechtigungsregistrierung, KDE KService Cache, systemd-Override, Nix-GC-Root und Rückfallkonfigurationen geprüft; DP-2 lokal aktiv.
- grabowski-job-271d89fa6b42: beide nativen Grafikmodi auf dem produktiven Port 3390 tatsächlich funktionsfähig: Progressive 390369 Fenster-/38237 Text-Pixel, H.264 386385 Fenster-/68645 Text-Pixel, jeweils korrekte Eingabe, TLS ausgewählt, DP-2 nach Disconnect zurück. Nur das abschließende Auslesen deaktivierter qCDebug-PAM-Journalmeldungen ergab einen unzutreffenden roten Gesamtstatus.
- grabowski-job-ecdb7430d12b: grüner Produktivtest mit einem Client ohne AVC420: normaler SSL/TLS-RDP-Handshake, 414598 geänderte Fenster- und 34798 Text-Pixel, exakte Eingabe in einer KDE-Anwendung des echten alex-Kontos; erneute Verbindung mit gültiger 1168x812-Bildausgabe, zweifache automatische Wiederherstellung von DP-2 ohne zusätzlichen Controller und ohne offenes Preimage.
- Die neue Version läuft über ein lokales User-systemd-Drop-in; der NixOS-Systemprofilwechsel war nicht erforderlich. Eine unabhängige read-only-Überprüfung des KRDP-cgroup-Prozesses und des zugehörigen Listeners wurde über Großer Adler durchgeführt; sie ersetzt die oben genannten echten Remote-Funktionstests nicht.
- Das bestehende KRDP-6.6-v4-Override und seine Desktop-Registrierung sind lokal unter ~/.local/share/krdpserver/krdp-unit-before-progressive-20261101.conf und krdp-desktop-before-progressive-20261101.desktop gesichert. Ältere Auto-GC-Roots bleiben erhalten.

**Grenze der Nachweise:** Diese Abnahme nutzt FreeRDP-Clients unter Xvfb auf dem produktiven Host. Die iPad-Windows-App muss weiterhin eigenständig auf tatsächliche Oberfläche, absoluten Zeiger, Gesten, Scrollen und Drag sowie den Neustartpfad geprüft werden. Der Windows-MSTSC-Client auf fotolabor ist als Profil eingerichtet, seine frühere fehlgeschlagene PAM-Anmeldung wurde nicht durch einen realen neuen Windows-Logintest ersetzt. Die zusätzlichen Nachweise sind nicht mit einer vollständigen iPad-/Fotolabor-Abnahme zu verwechseln.



## iPad-Fingertipp und RDP-Button-Position

Die Windows-App auf iPadOS kann einen Fingertipp als RDP-Pointer-Button-PDU mit Koordinaten, jedoch ohne vorgeschaltetes MOVE-PDU senden. KRDP 6.7.0 leitete im InputHandler nur den Button an FakeInput weiter: KWin betätigte damit die bisherige Zeigerposition statt der Tap-Position. Das erklärt den Befund: korrektes KDE-Bild, aber Fingertipps scheinbar wirkungslos. Der Fehler ist unabhängig von TLS/PAM und H.264/Progressive Encoding.

krdp-6.7.0-position-before-mouse-button-v1.patch emittiert vor jedem regulären Button-PDU eine absolute QMouseMove-Aktion mit den aus dem RDP-Paket empfangenen (x,y)-Koordinaten, danach unverändert den Down-/Up-Button. Der vorhandene Wayland-Fixed-Point- und Virtual-Output-Offset-Code wird unverändert wiederverwendet. Eine ähnliche Ursachenanalyse wurde für iPad-Touch-PDUs ohne MOVE in Devolutions/IronRDP Issue #1466 dokumentiert. Dies ist ein gezielter KRDP-Fix und keine nachträgliche Bild-/Maus-Skalierung. Die User-Unit und die registrierte KDE-Anwendung müssen auf denselben daraus gebauten Nix-Store-Pfad zeigen.

- Der acht-Patch-Build liefert /nix/store/rgldrc8llk7k44b70946lhhzh3rn4w1l-krdp-6.7.0.
- Geprüft: Nix-Kompilierung gegen das unveränderte KWin 6.6.6 und KRDP-Quellregressionen (grabowski-job-0877a0632610).
- Der zuvor geprüfte sieben-Patch-Build liegt weiterhin unter /nix/store/7rmym4cqlr327y2yij2fjbnd5dzx5zr4-krdp-6.7.0 samt GC-Root v5 als Rückfall.
- Noch keine iPad-Touch-Endabnahme allein durch den Build: Reale Tap- und Drag-Funktion muss erneut mit der Windows-App geprüft werden. Standard-FreeRDP-Klicks mit vorgeschalteter Mausbewegung sind dafür nicht repräsentativ.



### KRDP-Stop-Hänger bei aktiver iPad-Sitzung

Beim Umstieg auf den Klick-Fix am 1. November 2026 reagierte die alte KRDP-6.7.0-Prozessinstanz während einer noch aktiven iPad-Verbindung nicht auf systemd SIGTERM. Die standardmäßige Stop-Frist von 90 Sekunden wurde ausgeschöpft; systemd beendete den alten Prozess anschließend mit SIGKILL und stellte DP-2 wieder her. Die Transaktion wurde wegen eines zu kurzen 60-Sekunden-Client-Timeouts korrekt auf die vorherige v5-Version zurückgesetzt. Das ist ein Stopp-/Join-Hänger, kein KWin-Absturz.

Die produktive User-Unit enthält deshalb TimeoutStopSec=15s: künftig wird der KRDP-Prozess bei einem derartigen Stopp begrenzt beendet und das Wayland-Ausgabegerät freigegeben. Die KDE-Sitzung von alex, der physische Monitor und die v5-Rückfallkonfiguration bleiben unabhängig erhalten. Kein zusätzlicher Watcher oder Controller wird eingeführt.



## Produktive Abnahme des iPad-Tap-Fixes – 1. November 2026

- grabowski-job-0877a0632610: gezielter Quellpatch für RDP-Button-PDUs ohne MOVE erfolgreich auf die acht-Patch-Ableitung kompiliert.
- grabowski-job-48d782ad790c: KRDP-Regressions- und 59 NixOS-Systemquelltests bestanden; gepinnter Nix-Build reproduziert exakt /nix/store/rgldrc8llk7k44b70946lhhzh3rn4w1l-krdp-6.7.0, GC-Root ~/.local/share/krdpserver/krdp-ipad-native-v6 registriert.
- grabowski-job-2b0d4da19da5: erster Versuch während einer noch aktiven iPad-Sitzung blockierte beim alten KRDP-SIGTERM bis zum 90-Sekunden-Systemd-Timeout; der Job rollte korrekt zur vorherigen Version zurück, die physische Ausgabe DP-2 wurde wiederhergestellt.
- grabowski-job-297fb116431b: nach Beendigung der offenen RDP-Sitzung wurde der identische acht-Patch-Build erfolgreich auf dem produktiven Userdienst/Port3390 aktiviert. Nur KRDP wurde neu gestartet, keine KDE-Abmeldung und kein NixOS-Reboot; KWin-Desktopberechtigung, Userunit und GC-Root sind auf denselben Storepfad gebunden. Der 15s-Stop-Timeout ist live gesetzt und DP-2 lokal wieder aktiv.
- grabowski-job-2d587ee86e8f: wiederholter echter Test auf produktivem Port3390 mit vollständigem TLS-RDP-Login und normalem Maus-/Tastaturweg. Progressive-Client ohne AVC420: 380239 neue Fensterpixel und 30360 Textpixel, exakter Text. H.264-Client: 373335 Fensterpixel und 38091 Textpixel, exakter Text. Nach jeder Trennung kehrte der physische Monitor zurück, ohne gespeichertes Preimage.

Wichtig: Der sichtbare iPad-Desktop wurde vom tatsächlichen Nutzer nach der Progressive-Umstellung bereits bestätigt, jedoch **vor** dem neuen Click-PDU-Patch als nicht anklickbar gemeldet. Die erneute Touch-App-Endabnahme nach der v6-Aktivierung ist offen. Die FreeRDP-Regression mit Maus-MOVE vor Button beweist keine direkte iPad-Tap-Akzeptanz. Ein bloßes Weiterleiten von RDPEI-Multitouch-PDUs ist von diesem kleinen Button-PDU-Fix ebenfalls nicht abgedeckt.

Fotolabor (Windows 11) erreichte am 1. November um 15:52 über das bestehende RDP-Profil die produktive Verbindung und handelte TLS aus; der Server verweigerte anschließend wegen pam_authenticate failure den Login von alex. Der Windows-Ereignisbericht dokumentiert einen Abbruch der Verbindung, nicht den Absturz von mstsc.exe. Auf dem Windows-Konto wurden keine gespeicherten TERMSRV-Credentials für dieses Ziel gefunden. Daher sind das dort eingegebene Passwort und die erfolgreiche Windows-Endnutzeranmeldung nicht bestätigt. Keine Passwörter in Git/PR oder Testlogs ablegen.


## RDPEI-Touch (experimentell)

FreeRDP 3.32 enthält einen RDPEI-Multitouch-Server, den KRDP 6.7 bislang
nicht nutzt. Der optionale Quellpatch krdp-6.7.0-rdpei-touch-input-v1.patch
bindet dessen Dynamic Virtual Channel ein und überträgt den ersten aktiven
Finger als absolute Qt-Mausbewegungen, Tastendruck und Loslassen an den
bestehenden KWin-FakeInput-Pfad. Weitere Finger werden in dieser ersten
Variante ignoriert; Pinch- und Zwei-Finger-Scroll-Gesten sind noch nicht
implementiert. Die bisherigen normalen RDP-Maus-/Tastatureingaben bleiben
unverändert.

Der Kanal wird ausschließlich mit KRDP_RDPEI_TOUCH=1 eröffnet. Die
produktive Systemd-User-Unit aktiviert ihn auf einem gesondert gepinnten
KRDP-6.7.0-Build mit neun Patches.
Technische Vorabprüfungen:
- grabowski-job-1043bb0de0d9 und grabowski-job-b7914544ac6a:
  FreeRDP +multitouch sendet/öffnet den Microsoft-RDPEI-DVC; KWin-Video,
  gewöhnliche Maus-/Tastatureingaben und DP-2-Restore funktionieren weiter.
  Die Qt-Meldungen liegen im USER-Journal statt stdout: um 17:46:24 Uhr
  erschienen RDPEI_OPEN_CODE 0, RDP touch channel started und
  RDP touch input ready (job c1e8a6437d73).
- grabowski-job-ccdd315b086f und grabowski-job-851e1f10c545:
  Gegen das tatsächlich gebaute KRdp.so gelinkter C++-Qt-Test. Zwei
  nacheinander aktive Finger lieferten exakt neun erwartete QMouseEvents
  (Down, Move, Up, Koordinaten und Buttonzustände), zusätzliche Kontakte
  bei bereits gedrücktem Primärfinger wurden ignoriert. Test im
  isolierten Nix-Build, ohne Benutzerdesktop zu verändern.
- Die exakte Nix-Ableitung wurde erneut über build.sh reproduziert:
  /nix/store/nxpqvrpxqg69rszhbw222hyagkkwh9nb-krdp-6.7.0.

Noch nicht bewiesen: ein echter iPad-Fingertipp nach dieser Aktivierung.
Die Verbindung des Clients und die isolierte C++-Eingabeabnahme ersetzen
keinen tatsächlichen iPad-Windows-App-Test. Mehrfinger-Gesten, Pinch-Zoom
und Zwei-Finger-Scrollen sind mit diesem Patch nicht implementiert.


## RDPEI produktive Abnahme nach Aktivierung

- grabowski-job-446679e9a865: KRDP 6.7.0 mit neun Patches von der
  genau reproduzierten Nix-Quelle nxpqvrpxqg69rszhbw222hyagkkwh9nb
  aktiviert; gleiche ausführbare Datei in systemd-User-Unit und gezielter
  KWin-Desktopberechtigung, KRDP_RDPEI_TOUCH=1 im tatsächlichen
  Prozessenvironment, GC-Root krdp-ipad-native-v7 und vorheriges v6-Override
  samt Desktop-Preimage als Rückfall gesichert. Kein NixOS-Switch.
- grabowski-job-3dfdfc0462b3: Echte Verbindungsabnahme auf dem produktiven
  Port 3390 mit +multitouch und Progressive Encoding: RDPEI-Kanal bereit
  laut User-Journal, 412673 Pixel Fensteränderung, 40128 Pixel Textänderung,
  exakte Eingabe in eine bereits unter alex laufende KDE-Wayland-Sitzung,
  Trennung und Wiederherstellung von DP-2 ohne Preimage.
- grabowski-job-ccdd315b086f: aus dem gleichen KRdp-Build gelinkter
  Qt-QMouseEvent-Abnahmetest bestanden. Touch DOWN/UPDATE/UP, korrekte
  absolute Koordinaten, Button-Zustandsfolge und Ignorieren zusätzlicher
  Finger: neun von neun erwarteten Ereignissen.
- Eine reale Touch-Eingabe der iPad-Windows-App wurde noch nicht
  automatisiert bestätigt und bleibt ausdrücklich offen. Multi-Finger-Gesten
  sind in dieser minimalen Implementierung nicht unterstützt.


## Fotolabor: echter Windows-FreeRDP-Zugang, 1. November 2026

Die bisherige native Windows-11-MSTSC-Verbindung zu KRDP auf Port
3390 scheiterte beim TLS-only-Credential-Transfer. Ein Windows-
Prozessabsturz wurde nicht bestätigt. Das bisherige Desktopprofil
Fotolabor-Heim-PC-KRDP.rdp ist nach
%LOCALAPPDATA%\Heim-PC\rdp-backups\Fotolabor-Heim-PC-KRDP-retired-20261101.rdp
verschoben worden, damit es nicht mit dem funktionierenden Client
verwechselt wird.

Der neue primäre Desktoplink lautet Heim-PC KDE (FreeRDP).lnk und
startet %LOCALAPPDATA%\Heim-PC\clients\start-kde-rdp.cmd.
Es nutzt die lokal installierte FreeRDP-3.32.3-dev0-SDL-Binärdatei
sdl-freerdp-2114.exe mit SHA256
088F90B26C07CD55E1C95AB1923B1FF058B2CB7CFECB9761AF645192A30AA3C3.
Diese offizielle FreeRDP-CI-Nightly-Datei ist nicht digital signiert;
sie wurde nicht in Git oder das NixOS-Systemprofil übernommen.
Der Desktop-Link nutzt die Argumente
/v:heim-pc.tail6dbb90.ts.net:3390 /u:alex /from-stdin:force
/sec:tls /cert:ignore /w:1168 /h:812 /log-level:WARN.
Das Kennwort wird manuell im Konsolenfenster eingegeben und nicht
in Link oder Startskript abgelegt. Die ursprünglich verwendete
/gfx:progressive:on,AVC420:off,AVC444:off-Option ist in dieser
Windows-Variante nicht gültig; sie verursachte Exitcode -1000
vor der Netzwerkverbindung und wurde entfernt.

Tatsächlicher Windows-Test: FreeRDP auf fotolabor lief in der
interaktiven Windows-Sitzung 15 mit erfolgreicher Verbindung zum
echten KDE-Arbeitsplatz alex; das FreeRDP-GUI-Fenster war sichtbar
(Titel FreeRDP und Größe 1184x851). 32 synthetisch von diesem
Windows-Fenster versandte Zeichen erreichten eine xterm-Anwendung
im echten KDE-Konto. Vier automatisch gesendete Unterstriche
wurden als Fragezeichen empfangen; die übrigen Zeichen kamen
unverändert an. Dies ist eine Einschränkung der getesteten
SendKeys-Tastaturbelegung, kein Nachweis eines Fehlers bei
manueller Windows-Tastatureingabe.
Ein separater Pixelvergleich der Windows-Clientbilder fehlt.
Nach Trennung wurde DP-2 physisch wiederhergestellt.

Der Desktoplink wurde anschließend ohne ein vorgespeichertes
Kennwort gestartet; der FreeRDP-Clientprozess startete. Der
vollständige Weg mit der künftig manuellen Kennworteingabe am
Vater-PC ist noch nicht unabhängig durch einen Nutzer bestätigt.
Die iPad-Windows-App-Touch-Abnahme bleibt ebenfalls offen.
