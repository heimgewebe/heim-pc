# iPad-Zugang zum laufenden KDE-Plasma-Konto alex

## Aktueller iPad-Betriebsweg – 10. November 2026 (Gen71)

Die echte Microsoft Windows App zeigte auf dem iPad über den isolierten Tailnet-Port **3392** den virtuellen KRDP-Bildschirm **1168 × 768** ohne die zuvor sichtbare Bildstreckung. Daraus wurde der folgende **laufende**, auf dem neuen Port noch nicht vollständig nativ abgenommene Standardweg eingerichtet:

- **iPad:** `100.68.88.111:3390` → Tailscale Serve → `127.0.0.1:3390` → KRDP in der KDE-Wayland-Sitzung von `alex`. Extern 3390 ist jetzt **KRDP**, nicht mehr XRDP.
- **Bildschirm:** `ipad-krdp-monitor.service` erstellt mit dem vorhandenen KRFB-Helfer die Plasma-sichtbare Ausgabe `Virtual-iPadKrdp` mit **1168 × 768, Skalierung 1**; KRDP wählt sie mit `--monitor-name Virtual-iPadKrdp --plasma`. Das Plasma-Panel auf diesem Bildschirm (ID 44) umfasst Startmenü, Fensterleiste, Systembereich, Uhr und „Desktop anzeigen“.
- **Wiederherstellung:** Der virtuelle Monitor muss vor KRDP aktiviert werden. `recover-user.sh --check` kontrolliert deshalb die beiden Benutzer-Units und die gespeicherte Bildschirmdienstvorlage; `--apply` sperrt weiter bei aktivem RDP-Client und bewahrt für geänderte Konfigurationen Rückfallkopien.
- **Alte Wege:** Tailnet-Port **3391 ist entfernt**. Port 3392 ist nur als zeitlich begrenzter Test-/Rückfallweg vorgesehen; dessen temporäre Task und Tailscale-Freigabe dürfen nicht zu einer zweiten Dauerarchitektur werden. Das interne XRDP kann weiter auf 3389 lauschen, ist aber nicht mehr an Tailnet 3390 angebunden.
- **Grenzen:** Die echte Windows-App-Verbindung über **den neuen Port 3390**, Touch/Klick, Tastatur, Reconnect und eine physische Gen71-Approved-Bootpromotion sind noch nicht vollständig abgenommen. Die separaten KRDP-Tests und der RDP-Protokollhandshake ersetzen diese iPad-Gegenprobe nicht. RustDesk und Boot-Rückfallprofile sind unverändert. Die Plasma-Panel-Konfiguration liegt zunächst im Benutzerprofil, nicht deklarativ im NixOS-System.

**Ab hier historische Konfigurationen:** Die alten Angaben zu DP-2, :3391 und früheren Builds dokumentieren Entwicklungsstände; sie sind nicht mehr als aktuelle Betriebsanweisung zu verwenden.

## Historischer Produktivstand – 5. November 2026

## Produktiver KRDP-v13.1-Serverstand – 5. November 2026 (native iPad-Abnahme offen)

**Verbindlicher Weg:** Microsoft Windows App auf iPadOS → Tailscale `100.68.88.111:3391` → `127.0.0.1:3390` → KRDP im **bereits angemeldeten physischen KDE-Wayland-Desktop** von alex. Extern `:3390` führt zu XRDP, **nicht** zum physischen Desktop.

**Runtime (neuer DP-2-Namensselektor):** Am 05.11.2026 um 18:46:45 MEZ wurde der geprüfte KRDP-6.7.0-Build mit zusätzlichem `--monitor-name`-Patch aktiviert. `app-org.kde.krdpserver.service` läuft nach der Aktivierung mit PID `1680249`, `NRestarts=0`, und `/run/user/1000/krdp-ipad-native-v13/krdpserver --address 127.0.0.1 --port 3390 --monitor-name DP-2 --plasma`. Das ausgeführte ELF ist byteidentisch zu `/nix/store/zd0w8091nc839xdnm14yg8ax8dd6y9hk-krdp-6.7.0/bin/.krdpserver-wrapped` (SHA-256 `dd6bda0752ec1e33336865acc4e608a909be62d005f1b3ad23de2d9b746783f9`). Der separate GC-Root `~/.local/state/grabowski/krdp-ipad-native-v13-named-monitor` schützt den neuen Build; `krdp-ipad-native-v13` hält die vorherige, weiterhin rückrollbare Store-Closure. Das geprüfte `recover-user.sh --check` verifiziert Binärhash, User-Unit, KWin-Desktoprechte und GC-Root. Bei Verlust der User-Konfiguration ist die unten dokumentierte Recovery-Prozedur erforderlich; vollständig deklaratives First-Boot-Provisioning fehlt noch.

**Neue serverseitige E2E-Abnahme auf dem aktivierten Namensselektor:** Grabowski-Task `a89bb7baf43544c7ae054357` authentifizierte FreeRDP gegen den produktiven KRDP-Prozess `1680249` bei **beiden** aktiven physischen Monitoren. Das Clientbild war fortlaufend mehrfarbig/aktualisiert ohne Framefehler. KWin registrierte mindestens zwei unterschiedliche globale Zeigerpositionen **innerhalb von DP-2** (x von 2259 bis 3854), nicht mehr im Ursprung von DP-1. Der Lauf beendete den Client, entfernte das Testskript und bestätigte die unveränderte zweimonitorige KScreen-Topologie sowie `NRestarts=0`. Dies ist kein iPad-Windows-App-Test.

**Frische echte Server-E2E-Proben:** Grabowski-Task `4655878c1c674c83b3c608ca` authentifizierte sich gegen den laufenden v13, beobachtete laufend wechselnde, mehrfarbige Bilddaten und zwei unterschiedliche, von KWin bestätigte Mauspositionen. Task `249ffcea17194f0996acca6a` bestätigte im realen KDE-XWayland-Desktop über KRDP sechs Maus-Tastendrücke und sechs Freigaben einschließlich Links-/Rechtsklick, Radereignissen und Ziehen. Temporäres Fenster/Client entfernt; Dienst-PID und physische DRM-Anschlüsse unverändert. **Dies beweist weder die Funktion der echten iPad-Windows-App noch native Touch-Gesten.**

**Aktuelle Bildschirmtopologie:** Beide physischen Ausgänge sind laut DRM und KScreen aktiv: `DP-1` 3840×2160 bei Skalierung 1,7, logisch (0,0), `DP-2` 2560×1440 bei Skalierung 1,0, logisch (2259,0). Die logische Gesamtfläche ist 4819×1440. Qt meldete am 05.11. bei beiden Displays `QScreen[0]=DP-1` und `QScreen[1]=DP-2`; bei getrenntem DP-1 war Index 0 zuvor DP-2. `--monitor 0` konnte daher unbeabsichtigt den falschen physischen Ausgang wählen. **Der Patch löst den bevorzugten Namen `DP-2` für jede neue RDP-Verbindung frisch auf.** Wenn DP-2 wirklich fehlt, fällt er auf den ersten verfügbaren Ausgang zurück, ohne die Monitore umzuschalten.

**Windows-App-spezifische Konfiguration zur echten Abnahme:** In der Windows App **Einstellungen → Anzeige** Auflösung und `Vollanzeige verwenden` prüfen. Der geteilte 16:9-Monitor muss auf dem anders proportionierten iPad seitenverhältnistreu mit Randflächen dargestellt werden, nicht verzerrt in Vollbild gestreckt. In der Sitzung den **Mauszeigermodus** statt `Direct touch` wählen, wenn ein sichtbarer Zeiger erforderlich ist: Microsoft zufolge blendet `Direct touch` den Cursor aus. Der aktuelle RDPEI-Patch wandelt jeweils **einen** aktiven Kontakt in linke Mausbewegungs-/Tastenereignisse um; er ist **keine** vollständige Mehrfinger-Touchimplementierung. Rechtsklick, Rad und Gesten sind im Client-Mausmodus separat am echten iPad zu prüfen. Dokumentation: [Windows App – Anzeige](https://learn.microsoft.com/de-de/windows-app/display-settings) und [Windows App – Eingabemodi](https://learn.microsoft.com/en-us/windows-app/input-keyboard-mouse-touch-pen?tabs=ios-ipados).

**P0 weiterhin offen:** Das native iPad meldete zuletzt ein verzerrtes Bild und unbrauchbare Maus-/Touchbedienung. Ohne echte native Clientabnahme und bestätigte Hoch-/Querformatwechsel, Klicks, Touch, Reconnect, korrekte Cursorposition, richtige Einzelmonitor-Auswahl bei zwei verbundenen physischen Monitoren und Neustart-Wiederherstellung **nicht als vollständig repariert oder akzeptiert melden**. Die laufende Plasma-Sitzung und Monitore nicht zu Diagnosezwecken neu starten. PR #302 bleibt bis zur realen Abnahme entsprechend gekennzeichnet.

### Quellgebundene Wiederherstellung nach Benutzerprofilverlust oder Neustart

Im Repository steht ein idempotentes KRDP-v13-Recovery-Werkzeug. Es leitet den Store-Binärpfad **aus** der User-Unit-Quelle ab und vergleicht ihn mit der KWin-Desktopregistrierung, dem GC-Root und dem laufenden Prozess.

```bash
# Aus dem Repository heimgewebe/heim-pc als Benutzer alex:
bash runtime/krdp-ipad/recover-user.sh --check

# Nur wenn der Check einen tatsächlichen Fehler meldet:
# setzt aktive KDE-Wayland-Sitzung und keine bestehende RDP-Verbindung voraus
bash runtime/krdp-ipad/recover-user.sh --apply
```

`--check` liest ausschließlich den v13-Livevertrag. `--apply` sichert vor jeder Änderung die betroffenen Benutzerdateien, prüft die Store-Closure, installiert die KWin-Desktopberechtigung und startet **nur KRDP** neu. Im Fehlerfall werden die ursprünglichen Benutzerdateien wiederhergestellt und der frühere Dienstzustand erneut versucht. KDE, physische Monitore und die gebootete NixOS-Generation bleiben unangetastet. Fehlt der gepinnte Store-Build, zuerst `bash runtime/krdp-ipad/build.sh` ausführen und den neuen Pfad gegen beide Sourcevorlagen prüfen.

Der primäre Userdienst ist an `plasma-workspace.target` gebunden und aktiviert. Das ist ein **Startvertrag**, kein frischer Nachweis eines vollständigen Kaltboots samt erneuter iPad-Anmeldung.

**Clientgrenze laut Microsoft:** Die Windows App unter iOS/iPadOS unterstützt weder gleichzeitige Mehrmonitorübertragung noch dynamische Sitzungsauflösung. Der neue KRDP-Dienst überträgt deshalb stabil **DP-2 als einen physischen Desktopausgang** und wählt bei dessen Ausfall einen verfügbaren Ersatz, statt bei Hotplug still auf DP-1 zu wechseln. Ein exakter clientseitiger Seitenverhältnis-/Touch-Test der echten Windows-App steht weiterhin aus. [Microsoft: Plattformfunktionen](https://learn.microsoft.com/de-de/windows-app/compare-platforms-features).

## Historische Untersuchungen (1.–4. November 2026)

Die folgenden Abschnitte dokumentieren frühere v12-Stände und den damaligen Status »v13 noch nicht produktiv aktiviert«. Diese Angaben sind historisch und dürfen nicht als aktueller Betriebszustand interpretiert werden.

## P0-Nutzerbefund nach Neustart am 4. November 2026

**Die echte Microsoft Windows App auf dem iPad ist weiterhin NICHT nutzbar:** Der Nutzer bestätigt verzerrtes Bild sowie funktionslose Maus- und Touch-Eingabe. Frühere authentifizierte Linux-FreeRDP-Bild-, Pointer- und Tailnet-Tests bleiben technische Teilbelege und überstimmen diese native E2E-Beobachtung nicht.

**Neuer KWin-Blocker nach dem NixOS-Neustart um 13:40 MEZ:** Der produktive KRDP-v12-Dienst bleibt auf `/nix/store/9jac0lb4y5zxqd0nw1g8fsn0py9y7lq3-krdp-6.7.0` aktiv, aber KWin 6.6.6 verweigert `zkde_screencast_unstable_v1` und erzeugt keinen nutzbaren Bildstream. Ein gezielter KRDP-Userdienst-Neustart mit erneutem `kbuildsycoca6` beseitigte dies nicht; die Linux-FreeRDP-Gegenprobe blieb schwarz. Die KService-Abfrage mit dem nativen `KApplicationTrader::query()` ermittelt die korrekte Desktop-Registrierung und beide angeforderten Wayland-Interfaces (Job `grabowski-job-0a45eef8a82c`), doch die laufende KWin-Instanz bewirbt sie gegenüber KRDP oder einem temporär registrierten Testclient nicht (Jobs `grabowski-job-f90587b247b7` und `grabowski-job-c52c76645eb9`). Die Ursache innerhalb der laufenden KWin-Berechtigungsentscheidung ist **noch nicht nachgewiesen**; kein pauschaler KWin-Permission-Bypass und kein KDE-Neustart auf Verdacht.

**Tailscale:** Der während dieser Arbeiten abgelaufene Node-Schlüssel führte vorübergehend zu `NeedsLogin`. Der neueste Readback zeigt wieder `BackendState=Running`, und Tailscale Serve leitet `100.68.88.111:3391` auf den lokalen KRDP-Port 3390. Diese Wiederherstellung belegt nicht die Windows-App-Nutzbarkeit.

**Quellkandidat KRDP v13 – NICHT produktiv aktiviert:** 14 Patches, darunter ein notwendiger Embedded-Cursor-Modus auch für den physischen `createOutputStream()` (vorher wurde der getrennte Cursor unterdrückt, ohne ihn einzubetten), sowie eine über `KRDP_INPUT_DIAG=1` aktivierbare, begrenzte Diagnose ausschließlich aggregierter Maus-/Touch-Eingangsereignisse ohne Koordinaten. `build.sh` reproduziert `/nix/store/2gzx8hw3mjgid4zw570js4fg7ck9cgvx-krdp-6.7.0`; 16/16 zielgerichtete Tests bestanden. Die isolierten Authentifizierungsversuche lieferten wegen der laufenden KWin-Screencast-Sperre keinen auswertbaren Bildstream. Die Sourcevorlagen sind auf diesen Kandidaten vorbereitet, während die tatsächliche Benutzer-Unit weiterhin v12 nutzt. Vor Aktivierung sind exakter Revisions-/Runtime-Readback, GC-/Rollback-Sicherung und positive Screencast-Gegenprobe erforderlich.

## Historischer produktiver Stand – 4. November 2026

**Verbindlicher Nutzerweg:** Microsoft Windows App auf dem iPad → `heim-pc.tail6dbb90.ts.net:3391` (alternativ `100.68.88.111:3391`) → Tailscale Serve → KRDP `127.0.0.1:3390` → bestehende KDE-Wayland-Sitzung von `alex`. Extern `:3390` ist dagegen XRDP und **nicht** der geteilte KDE-Desktop. Der Host läuft auf der tatsächlich gebooteten NixOS-Gen46 mit KDE Plasma/KWin 6.6.6.

**Aktueller Betriebsmodus:** gepinnter KRDP 6.7.0 mit dreizehn Quellpatches, einschließlich physischer Ausgabebreite (`screen->size()`) und korrektem Zeiger-Monitorursprung (`QScreen::geometry()`); `--monitor 0 --plasma` statt virtuellem 1168×812-Monitor. Exakter mit `./runtime/krdp-ipad/build.sh` reproduzierter Storepfad: `/nix/store/9jac0lb4y5zxqd0nw1g8fsn0py9y7lq3-krdp-6.7.0`. Die Benutzer-Unit `app-org.kde.krdpserver.service` startet den Qt-Wrapper `bin/krdpserver`; die KWin-Anwendungsberechtigung `org.kde.krdpserver-ipad-test.desktop` muss dagegen auf **dieselbe Nix-Store-Ableitung**, aber auf das tatsächliche ELF `bin/.krdpserver-wrapped` zeigen. KWin 6.6.6 vergleicht den kanonischen `Exec`-Pfad mit `/proc/PID/exe` und nicht mit dem systemd-Startargument. Nach der Änderung ist ein kontrollierter KRDP-Dienstneustart erforderlich, damit KWin nicht mehr die alte Wayland-Verbindungsberechtigung zwischenspeichert. `KRDP_EMBED_CURSOR=1` und `KRDP_RDPEI_TOUCH=1` bleiben gesetzt. Ein systemd-Benutzer-Drop-in und die Desktop-Registrierung liegen lokal unter `~/.config/systemd/user/app-org.kde.krdpserver.service.d/override.conf` und `~/.local/share/applications/org.kde.krdpserver-ipad-test.desktop`. Die beiden Dateien dieses Verzeichnisses sind die zugehörigen wiederherstellbaren Sourcevorlagen, nicht der Nachweis eines bereits vollständig deklarativen NixOS-Aktivierungswegs.

**Nachweise:** Der zusätzliche Pointerpatch wurde separat mit authentifizierten RDP-Eingaben auf DP-1 (3840×2160, Skalierung 1,7) und DP-2 (2560×1440, Skalierung 1, Offset 2259) jeweils an fünf Positionen exakt gegen KWin gemessen. Der komplette Nix-Build des PR #302 ergibt denselben Storepfad wie der gestartete Produktivdienst. Am 4.11. um 07:12 Uhr authentifizierte eine RDP-Verbindung und öffnete RDPEI, aber das Journal meldete wiederholt `PipeWire frame did not contain usable image data`; der Clienttransport brach um 07:17 Uhr ab. **Ein fehlerfreies natives iPad-Bild sowie Maus, Fingertipps, Ziehen, Scrollen, Tastatur und Reconnect sind weiterhin nicht abgenommen.** Die Juno-Python-Umgebung kann die iPad-Windows-App nicht selbst bedienen.

**RDP-Grafik-Acknowledgements:** Aus KDE Upstream `fe0037384404b74895bff5a5f4cf411a62f1c712` (Bug 520260) ist die Behandlung von `SUSPEND_FRAME_ACKNOWLEDGEMENT` auf den gepinnten KRDP-6.7.0-Quellstand zurückportiert. Der neue Patch verhindert, dass gesendete Frames bei ausdrücklich pausierten Client-ACKs den Frame-Puffer für immer blockieren, und berücksichtigt beide 6.7-Codec-Wege (H.264 und Progressive). Exakte Quelle und Tests ergeben v11 `/nix/store/h97rxnpv402zv7bnl9grqvk54v95ncq5-krdp-6.7.0`; Produktiv-PID und physischer DP-2-Ausgang wurden nach dem kontrollierten Dienstwechsel überprüft. Eine erste synthetische TCP-Verbindung unmittelbar nach einem Restart löste beim neuen Prozess einen SIGSEGV in der KWin-FakeInput-Initialisierung aus; systemd startete ihn neu. Eine weitere kontrollierte TCP-Vorverbindung nach der Initialisierung verursachte keinen erneuten Absturz. Das muss bei echten Anmeldungen beobachtet werden: weder ist damit die grundsätzliche Start-Race behoben noch die native iPad-Grafik bereits abgenommen.

**KWin-Screencast-Freigabe und Absturzschutz (4. November, 09:31 MEZ):** Ein wirklich beobachteter SIGSEGV in `wl_proxy_get_version` bei einer noch ungebundenen FakeInput-Schnittstelle wird in der v12-Binärversion durch einen `isActive()`-Guard verhindert. Die Ursache des danach verbleibenden fehlenden Bildstreams war zusätzlich ein Berechtigungsabgleich: KWin suchte das echte Prozess-ELF `.krdpserver-wrapped`, der Benutzer-KService-Eintrag hatte jedoch nur das äußere `krdpserver` deklariert. Eine temporär korrigierte Registrierung mit *neuem* isoliertem KRDP-Prozess auf Port 3392 beseitigte die Screencast-/Nullparameter-Warnungen (Job `grabowski-job-4f2acce7e264`); die nach derselben Korrektur neu gestartete Produktiv-KRDP-Instanz bestand den gleichen frühen Clienttest ohne solche Warnungen und ohne Änderung an DP-2 (Job `grabowski-job-97e2c2df325d`, PID 341341). Eine Registrierungskorrektur ohne neuen KRDP-Prozess genügt nicht, da KWin bereits pro Wayland-Client zwischengespeicherte Schnittstellenrechte weiterverwendet. **Diese Belege sind echte KWin- und Prozesskorrekturen, keine authentifizierte Video-/Touch-Endabnahme der Windows-App auf dem iPad.**

**Authentifizierter Live-Grafik- und Zeigernachweis (4. November, 11:39–11:45 MEZ):** Mit dem produktiven v12-Dienst (PID 341341, `NRestarts=0`) authentifizierte sich ein FreeRDP-3.32-Client im abgeschirmten Xvfb-Display über `127.0.0.1:3390` mit Progressive-RDPGFX. Der Client zeigte nach dem initialen Schwarzbild mehrfarbige Pixel; zwei gesteuerte Mausbewegungen erzeugten unterschiedliche reale `workspace.cursorPosChanged`-Ereignisse in KWin (Job `grabowski-job-9fdc2fa3c278`). Ein zweiter authentifizierter Lauf zeigte das **fortlaufend aktualisierte Desktopbild**: Ein nur kurz lokal auf dem echten KWin-Desktop eingeblendetes X11-Farbfenster wurde eingefärbt, umgefärbt und wieder entfernt; im entfernten FreeRDP-Bild änderten sich jeweils 178, 35 und 86 von 2204 untersuchten Pixelpositionen (Job `grabowski-job-413d57f3c0e9`). Bilddaten wurden nur im Arbeitsspeicher ausgewertet, keine Desktopaufnahmen gespeichert; sämtliche Testfenster, Xvfb-Prozesse und temporären Dateien wurden entfernt. DP-2 war nach beiden Verbindungen unverändert, der produktive KRDP-Prozess blieb stabil. Die gelegentliche Meldung `PipeWire frame did not contain usable image data` trat beim ersten Test weiterhin auf, obwohl die zweite Probe echte neue Bilder bestätigte; sie allein ist kein Beweis eines stehenden Bildes. **Nachgewiesen sind damit reale FreeRDP-Authentifizierung, dynamische Desktop-Bildübertragung und Zeigerbewegungen, aber weder die echte native iPad-Windows-App noch Touch, Klick, Ziehen, Scrollen, Tastatur oder Wiederverbinden.**

**Monitore und Rückfall:** Bei der aktuellen Live-Abfrage meldete der DRM-Kernel DP-2 als verbunden und DP-1 als *disconnected*. KScreen zeigte DP-2 allein bei 2560×1440, Skalierung 1, Position 0,0. Das ist kein Beleg, dass die frühere Zweimonitor-Anordnung nach der aktuellen Verbindung wiederhergestellt wurde; sie darf auch nicht ohne physischen Anschlussstatus erzwungen werden. Der optionale `krdp-ipad-display-controller.service` bleibt deaktiviert. Vor Serverwechsel aktive RDP-Verbindungen ausschließen; bei einer Regression das lokal gesicherte vorige User-Drop-in und den KWin-Desktop-Eintrag zusammen zurückstellen. Gen46-Boot und Gen38-Recovery unverändert lassen.

**Wiederherstellung der Benutzerkonfiguration:** Nach einer Wiederherstellung des Repositories und der KDE-Benutzerdateien zuerst `./runtime/krdp-ipad/build.sh` ausführen und den ausgegebenen Storepfad gegen `ExecStart=` und `Exec=` in den beiden Sourcevorlagen prüfen. Diese Vorlagen sind für den am 4. November gebauten Gen46-Stand konkret ausgefüllt; bei einer anderen Nixpkgs-/KWin-Basis müssen **beide** Pfade gemeinsam auf den dann tatsächlich gebauten KRDP-Pfad aktualisiert werden. Die aktive Binärversion wird über `/home/alex/.local/state/grabowski/krdp-ipad-native-v12` vor Nix-GC geschützt. v11, v10 und v9 bleiben als vorherige KRDP-Rückfall-Versionen erhalten.

**Historische Wiederherstellungsanweisung (v12, nicht mehr ausführen):** Der alte Name `org.kde.krdpserver-ipad-test.desktop` gehört zu einer früheren Store-ELF-Berechtigung; er darf nicht mit der aktuellen v13-Unit vermischt werden. Stattdessen ausschließlich die obige `recover-user.sh`-Prozedur verwenden.

Die Dateien in `~/.config/systemd/user/` und `~/.local/share/applications/` bleiben über normale Wiederanmeldung und einen NixOS-Neustart erhalten. Für den Verlust beider Benutzerdateien ist die obige, erneut ausführbare Restore-Prozedur notwendig; ein vollständig deklaratives Provisioning aus NixOS-Systemquellen ist damit **noch nicht** realisiert. KRDP- und KWin-Registrierung vor dem Start stets auf denselben Store-Build abgleichen.

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
