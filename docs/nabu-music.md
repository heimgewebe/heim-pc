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

## Kontrollierte Wiederherstellung

1. Bei fehlender Nabu-Integration Home Assistant stoppen, ausschließlich
   `__init__.py`, `llm.py` und `manifest.json` in
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