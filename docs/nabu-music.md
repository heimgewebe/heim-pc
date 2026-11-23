# Nabu-Musik auf dem Heim-PC

## Bestandteile und dauerhafte Pfade

Nabu benutzt Home Assistant (lokales Ollama/Assist), Music Assistant mit Qobuz und den
Sendspin-Player `Nabu-Musik-MOTU` am MOTU M2. Das tatsächlich erprobte LLM-Werkzeug
`nabu_web__play_music` in `llm.py` ruft `music_assistant.play_media` für
`media_player.nabu_musik_motu` auf. Der produktive Ollama-Assist-Test mit
„Spiele Bakerman von Laid Back über Qobuz am Heim-PC“ ergab einen ausgeführten
Service-Aufruf, `playing` und einen aktiven PipeWire-Stream zum MOTU M2
(20. November 2026).

Die Dateien dieses Verzeichnisses sind **Quellkopien** des erprobten Stands,
nicht die automatisch aus NixOS erzeugte Home-Assistant-Konfiguration.
Die produktiven Dateien liegen unter
`~/.local/share/heimgewebe/home-assistant/custom_components/nabu_web/`.
Home Assistant bindet das gesamte persistente
`~/.local/share/heimgewebe/home-assistant` als `/config` ein;
Music Assistant entsprechend `~/.local/share/heimgewebe/music-assistant`
als `/data`. Ein gewöhnlicher NixOS-Generationswechsel löscht diese
Host-Verzeichnisse nicht.

Die Qobuz-Anmeldung, Ollama-Konversationsoptionen und das in Home Assistant
eingestellte `llm_hass_api=["assist"]` liegen in **privater Runtime-Konfiguration**,
insbesondere in Home Assistants `.storage`. **Keine dieser Dateien oder
Zugangsdaten ins öffentliche Git-Repository kopieren.**

## Sendspin und Nix-Garbage-Collection

Die Sendspin-User-Unit liegt unter
`~/.config/systemd/user/heimgewebe-music-sendspin.service`, ihr optionaler
MOTU-Hotplug-Starter unter `~/.config/systemd/user/heimgewebe-music-sendspin.path`.
Dieses Verzeichnis enthält die entsprechenden wiederherstellbaren Vorlagen.
Die öffentlichen Vorlagen erkennen das MOTU M2 mit einem **Modell-Glob**
(`usb-MOTU_M2_*`) und einem Audio-Sink-Präfix; sie enthalten keine
eindeutige Geräte-Seriennummer. Lokale Seriennummern gehören nur in
private Hostdaten. `python3 nixos/system/tests/test_nabu_public_web.py` prüft
numerische Loopback-Adressen, private DNS-Antworten und Redirect-Sperren.

Die Unit verwendet **keinen absoluten Nix-Store-Hash** mehr. Ihre PortAudio-Suche
läuft über den stabilen user-eigenen GC-Root
`~/.local/state/heim-pc/nabu-portaudio-gcroot/lib`.
Dessen Symlink wurde am 20. November 2026 durch `nix-store --realise
--add-root` angelegt; `nix-store --query --roots` bestätigte die direkte
GC-Verwurzelung. Er bleibt bei gewöhnlichem Rebuild/Generationswechsel erhalten,
solange die User-Daten erhalten bleiben und der Symlink nicht gelöscht wird.

**Wiederherstellung nach einem vollständigen Geräte- oder Store-Verlust:**
PortAudio aus der passenden Nixpkgs-Version installieren bzw. realisieren;
anschließend den GC-Root auf die neu vorhandene PortAudio-Store-Closure
setzen. Ein bloß zurückkopierter Symlink auf einen *fehlenden* Nix-Store-Pfad
ist kein Recovery-Nachweis. Die vorliegende Unit benötigt eine existierende
PortAudio-Library unter `nabu-portaudio-gcroot/lib`.


## Browser: öffentliche Ziele ohne zusätzlichen Dienst

`nabu-browser.service` verwendet den ebenfalls versionierten
`nixos/system/nabu/browser_proxy.py` als **Launcher für den bisherigen Chrome**:
Die Unit startet denselben Chrome-Prozess mit den bisherigen Flags, aber über
`python3 .../browser_proxy.py -- .../google-chrome ...`.

Der Launcher öffnet einen **temporären, nur an Loopback gebundenen SOCKS5-Port**
im selben Prozess und konfiguriert Chrome für HTTP(S)-Requests mit
`--proxy-server=socks5://127.0.0.1:<dynamischer-port>`,
`--proxy-bypass-list=<-loopback>` und ohne direktes DNS, QUIC oder
unproxied WebRTC-UDP. Der Proxy löst Ziele selbst auf und verbindet
ausschließlich mit der **vorab geprüften, konkreten öffentlichen IP-Adresse**.
Private IPv4/IPv6-Adressen, numerische Kurzformen, gemischte DNS-Antworten,
LAN-Ziele sowie Redirects und Link-Klicks zu solchen Zielen werden verweigert.
Bei einem Proxy-Ausfall gibt es keinen `DIRECT`-Fallback für Chrome-HTTP(S).

**Wichtig:** Beim Wiederherstellen von `nabu-browser.service` den bestehenden
`ExecStart`-Chrome-Aufruf unter Beibehaltung seiner privaten lokalen
Startparameter in den Launcher einschließen. Der Launcher benötigt weder eine
statische Proxy-Portnummer noch eine zweite User-Unit. Ein Start von Chrome
**ohne Launcher** würde diese Browser-Netzgrenze umgehen. Die anlaufende
Browser-Unit muss den aktiven Launcher verwenden; der Git-Quellcode allein
ändert keinen laufenden Dienst.

Tests: `python3 nixos/system/tests/test_nabu_browser_proxy.py` für
private und gemischte DNS-Ziele, SOCKS5-Protokoll und öffentlichen Tunnel;
anschließend einen echten Headless-Chrome-Request zu einer öffentlichen Seite,
zu einer privaten Adresse und zu einem per Klick erreichbaren privaten Link
über den Chrome-Debugkanal prüfen. Die Netzgrenze gilt für den
Chrome-HTTP(S)-Browserweg, **nicht** als systemweite Firewall. Nabus
`nabu_web__play_music` benötigt diesen Browser-Proxy nicht.

## ChatGPT Plus (optional) und Grabowski-Operator (Nabu Assist)

Diese Integration ergänzt den vorhandenen lokalen Assistenten und
ersetzt ihn nicht. Der optionale Modus `answer` verwendet die **offizielle
OpenAI-SIWC-OAuth-Anmeldung** und `/v1/responses` mit `store=false,
stream=true`. Die Browsermodi verwenden hingegen die bereits bestehende
ChatGPT-Websitzung. **Kein** ChatGPT-Browser-Scraping, API-Key,
Client-Secret, Zugriff auf ChatGPT-Verläufe oder offene Portfreigabe.

**Einmalige persönliche Anmeldung am Heim-PC** (Browser muss auf demselben
Rechner wie die Loopback-Rückrufadresse laufen):

```sh
python3 -B /home/alex/.local/share/heimgewebe/home-assistant/nabu-chatgpt-login.py
```

Der Befehl öffnet den OpenAI-Anmeldedialog im Browser. Dort muss die betroffene
Person selbst den Account auswählen und die Berechtigung
`chatgpt.tokens.use.direct` freigeben. Ein iPad-Browser auf einem anderen
Gerät erreicht den `127.0.0.1`-Callback des Heim-PC **nicht**. Die
Anmeldung darf nicht im Hintergrund fingiert werden. Falls der Browser nicht
öffnet, zeigt das CLI die offizielle Autorisierungsadresse zum Öffnen **auf
dem Heim-PC**. Der Login verwendet die Python-Standardbibliothek. Die
RSA/JWKS-ID-Token-Signatur, Audience, Nonce, Issuer und Ablauf werden bei
der Rückgabe kontrolliert.

Das CLI speichert den stabilen Host-Identifier und OAuth-Tokens ausschließlich
in Owner-privaten Dateien unter
`~/.local/share/heimgewebe/home-assistant/`, insbesondere
`.nabu-chatgpt.json` (0600). Das ist der persistente Host-Pfad von
Home Assistants `/config`-Mount. Datei/Token niemals in Git, Terminalprotokolle
oder externe Dienste kopieren. Der eingeschränkte `nabu_web__chatgpt`-Aufruf
nutzt ein vom aktuellen Account gelistetes Modell, verlängert Tokens
bei Bedarf und akzeptiert nur vollständig bestätigte Streaming-Antworten.
Bei fehlender/abgelehnter Autorisierung, Limits oder API-Ausfall bleiben
die lokalen Modelle nutzbar.

### Textchat statt Sprachchat als Standard

Bei einem ausdrücklich an ChatGPT gerichteten Auftrag nutzt Nabu standardmäßig
`nabu_web__chatgpt` mit `mode=browser_chat` und dem gesprochenen Auftrag
als `question`. Dadurch öffnet Grabowski die **normale Desktop-Chrome-Sitzung**
mit `https://chatgpt.com/?prompt=<urlkodierter Auftrag>`. Dies ist ein
vorbereiteter Eingabeentwurf, **kein Beweis, dass ChatGPT die Nachricht
abgesendet, beantwortet oder mit einem Plugin bearbeitet hat**. Ohne den lokal aktivierten Chrome-Sendehelfer prüft der Nutzer
das Eingabefeld und betätigt **Senden** selbst. Der Link eröffnet
üblicherweise einen neuen Chat; er ist keine dauerhafte
Bidirektionalschnittstelle für eine bestimmte Chat-Unterhaltung.

Nur bei ausdrücklichem `ChatGPT Live`, `Voice` oder `Sprachmodus` verwendet
Nabu `mode=browser_voice`. Eine unmittelbar an Nabu gerichtete Antwort aus
dem verknüpften ChatGPT-Konto bleibt separat als `mode=answer` verfügbar.
Die vorhandenen Home-Assistant-Gerätewerkzeuge bleiben unverändert bei Nabu;
nach dem Absenden kann ChatGPT seine tatsächlich verbundenen Plugins selbst
aufrufen. Nabu liest keine ChatGPT-Webantworten oder Browserkonto-Daten aus.

**Vertraulichkeit:** Der vorbefüllte Auftrag erscheint als URL-Parameter und
kann in Chrome-Verlauf sowie lokalen Grabowski-Taskprotokollen auftauchen.
Keine Passwörter, Zugriffstokens oder andere Geheimnisse über diesen
Textlink übergeben. Die URL-Länge ist absichtlich begrenzt.

**Automatisches Senden im normalen Chrome:** Nabu signiert Textaufträge
nach Installation des lokalen Sendehelfers mit einer kurzlebigen HMAC-Signatur.
Die eigens für `https://chatgpt.com/*` gebaute Manifest-V3-Erweiterung
reagiert ausschließlich auf exakt signierte Nabu-Links, kontrolliert den
vorausgefüllten Text und die sichtbare Senden-Schaltfläche und klickt
höchstens einmal. Externe Links mit nur `?prompt=` können dadurch keinen
automatischen ChatGPT-Auftrag auslösen. Kein Browser-Scraping von Antworten,
keine Chrome-Cookies in Nabu und keine fremde Erweiterung.

Die lokale Installation erfolgt über
`python3 nixos/system/nabu/setup_chatgpt_sender.py` im Heim-PC-Repo.
Sie bewahrt einen privaten Schlüssel in
`~/.local/share/heimgewebe/home-assistant/.nabu-chatgpt-autosend.key`
und erstellt die entpackte Chrome-Erweiterung unter
`/home/alex/.local/share/heimgewebe/nabu-chatgpt-autosend-extension`.
**Einmalig in der bereits angemeldeten normalen Chrome-Sitzung:**
`chrome://extensions` öffnen, Entwicklermodus einschalten,
**Entpackte Erweiterung laden** und genau diesen Verzeichnispfad wählen.
Danach die ChatGPT-Seite einmal neu laden. Dafür muss kein Browserprofil
kopiert, kein zusätzlicher Dienst geöffnet und kein Chrome-Prozess beendet
werden.

Bis die Erweiterung in Chrome aktiviert und ihr Sendeklick an einem echten
ChatGPT-Auftrag beobachtet wurde, ist **nur die Vorbereitung des Sendeversuchs**
nachgewiesen. Nabu behauptet keine tatsächlich gesendete Nachricht und
keine erfolgte Pluginaktion ohne entsprechenden Nachweis; der Nutzer kann
weiterhin manuell auf **Senden** klicken.

**Grabowski** wird über den bestehenden lokalen Streamable-HTTP-MCP-Endpunkt
`http://127.0.0.1:18181/mcp` angesprochen. Dieser muss **aus dem aktiven
HA-Container-Netzkontext** erreichbar sein, nicht nur vom Host. Die
Nabu-Werkzeuge sind:

- `nabu_web__grabowski`: `status`, `tasks`, `task` mit exakter Task-ID;
  enthält nur begrenzte Statusfelder und bestätigte Receipts.
- `nabu_web__grabowski_request`: nur auf ausdrücklichen persönlichen Auftrag
  legt der bestehende Grabowski-Operator eine dauerhafte `operator-obligation`
  mit eindeutigem Ziel und überprüfbarem Erfolgskriterium an. Der bestehende
  `transport-roundtrip`-Grip bindet den exakten MCP-Zielaufruf einmalig;
  der Client prüft sowohl die Transport- als auch die Ziel-Receipt.
  **Registrierung ist nicht Ausführung**, kein automatisch gestarteter
  Agentenlauf und keine Bureau-Queue-Promotion. Dafür ist die spätere
  normale Operator-Bearbeitung nötig.

Ein neuer beliebiger Shell-/Git-/Root-Aufruf über Nabu ist absichtlich
nicht verfügbar. Sprachbefehl z. B. »Nabu, wie geht es Grabowski?« oder
»Nabu, beauftrage Grabowski mit einer Prüfung der nächsten offenen Nabu-Aufgabe;
Erfolg ist ein belegter Status mit Task-Referenz«. Erfolgreiche
Quell- und Unit-Tests allein ersetzen weder den frischen HA-Tool-Readback
noch einen echten Assist- und Authentifizierungsdurchlauf.

**Dateien für den bestehenden persistierten HA-`nabu_web`-Runtimepfad:**
`__init__.py`, `manifest.json`, `llm.py`, `radio.py`,
`grabowski_client.py` und `chatgpt_client.py` werden als Package
zusammen benötigt. `siwc_login.py` bleibt das Host-Loginprogramm und
muss nicht in Home Assistant importiert werden. Ein Git-Merge allein
installiert diese Quellen nicht; aktivieren/abnehmen erst über den
bestehenden Nabu-HA-Runtime-Rollout und Neustart mit Tests.

## Internetradio

Live-Radio läuft über den nativen **RadioBrowser-Provider** von Music Assistant
auf demselben Player `media_player.nabu_musik_motu`; es gibt keinen zweiten
Audiostack, kein Abo und kein Login. `nixos/system/nabu/radio.py` ordnet
gesprochene Sender und Genres 30 kuratierten RadioBrowser-IDs zu, nicht
festen Stream-URLs. Andere Sender gehen mit `media_type=radio` als Namenssuche
an das RadioBrowser-Verzeichnis. Songs, Alben und Künstler bleiben bei Qobuz,
etwa „Radio Ga Ga“ oder Radiohead. `action=stop` stoppt die Wiedergabe.

Der Provider löst seinen API-Host per **SRV-DNS** auf. Die FritzBox beantwortet
`_api._tcp.radio-browser.info` nicht, deshalb steht im privaten Quadlet
`heimgewebe-music-assistant.container` nach `DNS=192.168.178.1` zusätzlich
`DNS=9.9.9.9`. Fehlt dieser Eintrag, lädt RadioBrowser mit einem DNS-Timeout nicht.
Provider-Eintrag und Quadlet sind Host-Runtime und werden nicht durch Git installiert.

## Kontrollierte Wiederherstellung

1. Bei fehlender Nabu-Integration Home Assistant stoppen, ausschließlich
   `__init__.py`, `llm.py`, `radio.py`, `grabowski_client.py`,
   `chatgpt_client.py` und `manifest.json` in
   `custom_components/nabu_web/` zurückkopieren und Home Assistant starten.
   Bestehende Runtime-Konfiguration nicht durch Quellkopien überschreiben.
2. Falls Sendspin-Units fehlen: die beiden Versionen aus diesem Verzeichnis
   in `~/.config/systemd/user/` installieren, vorher den GC-Root prüfen und
   anschließend `systemctl --user daemon-reload` sowie
   `systemctl --user enable --now heimgewebe-music-sendspin.path` ausführen.
   Sendspin selbst bleibt geräteabhängig und darf den User-Desktop ohne
   angeschlossenes MOTU nicht blockieren.
3. `systemctl --user status heimgewebe-homeassistant.service
   heimgewebe-music-assistant.service heimgewebe-music-sendspin.path`,
   `nix-store --query --roots "$(readlink -f
   ~/.local/state/heim-pc/nabu-portaudio-gcroot)"` und
   `wpctl status` prüfen. Die `nabu_web`-Integration und
   `llm_hass_api=["assist"]` im produktiven HA bestätigen.
4. Einen echten Sprachauftrag („Nabu, spiele Bakerman von Laid Back“)
   prüfen: Music-Assistant-Queue, Playerzustand, PipeWire-MOTU-Ausgabe
   und **hörbaren Ton** getrennt bewerten. Weder grüner Dienst noch
   Git-Merge ist allein eine Audio-Endabnahme.

Die vollständige Nutzerumgebung wird durch den bestehenden
`restic-backups-heim-pc`-Plan grundsätzlich unter `/home/alex`
erfasst. Private Ausschlusslisten und frische Restore-Proben sind
gesondert zu prüfen; die Git-Dateien allein ersetzen kein Backup.
