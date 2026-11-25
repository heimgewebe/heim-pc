# Nabu Assist: wiederherstellbares Sprachprofil

Dies ist die nichtprivate, additive Quelle für den am 24.11.2026 auf dem
Heim-PC erprobten Assist-Stand. Die sechs Dateien des HA-Custom-Components
werden weiterhin über den bestehenden Nabu-Paket-Deploy verwaltet; dieses
Profil baut **keinen zweiten Deployment-Dienst** auf. Ein Git-Merge aktiviert
das Profil nicht automatisch.

## Bestand

- `profile.json`: beobachtete Runtime- und Modellidentitäten, deutsche
  Pipelineoptionen und Zielpfade. OCI-IDs und RepoDigests bezeichnen den
  getesteten Bestand, nicht eine Behauptung über das jeweils neueste Image.
- `native_commands.yaml`: additive deutsche HassLightSet-Sätze, die Farben
  Lila/Hellgelb/Türkis, eindeutige Musik-Stopp-Befehle und explizite
  Farbaufträge für den Wohnzimmerprojektor. Unbekannte Ziele, Fragen,
  Negationen und mehrdeutige Mehrfachbefehle bleiben beim normalen Fallback.
- `native_intent_scripts.yaml`: NabuStopMusic und NabuProjectorDifferentColor.
  Die bestehende Music-Assistant-Entität `media_player.nabu_musik_motu`
  muss vorhanden und verwendbar sein. Der Handler ruft `media_stop`, nicht
  `media_pause` auf.
- `prompt-addendum.txt`: zusätzliche Regel für kompakte Werkzeugentscheidungen
  und frische Grabowski-Auftragsstatusabfragen. Sie wird einmal an den
  vorhandenen privaten Nabu-Systemprompt angefügt, nicht statt seiner geladen.

## Anwendung / Recovery

Zuerst den vorhandenen persistenten HA- und Assist-Bestand aus einem
verifizierten Restic-Snapshot wiederherstellen. Der übliche NixOS-Rebuild
behält diese Home-Verzeichnisse; der bloße Fortbestand des Verzeichnisses
beweist allerdings keine vollständige Wiederherstellbarkeit. Keine vollständige
`.storage`-Datei, Zugangsdaten, persönliche Gerätealiase, Browserprofile
oder private Prompts nach Git übernehmen.

Bei fehlenden oder abweichenden Profilbestandteilen:

1. Existierende HA-Konfiguration und relevante User-Units sichern; aktive
   Modell- und Dienstidentitäten mit `profile.json` abgleichen. Bei Bedarf
   fehlende Modellartefakte aus der gesicherten bzw. genau gepinnten Quelle
   wiederherstellen. Die SHA-256- und Größenangaben beziehen sich auf
   die vollständigen Dateien; Teildownloads sind kein gültiger Modellbestand.
2. Die native Grammatik nach
   `~/.local/share/heimgewebe/home-assistant/custom_sentences/de/nabu_native_commands.yaml`
   übernehmen. Die vorhandene `nabu_music.yaml` bleibt erhalten.
   Die beiden Blöcke aus `native_intent_scripts.yaml` unter dem vorhandenen
   `intent_script:`-Mapping ergänzen, nicht die vollständige
   `configuration.yaml` ersetzen. Bereits abweichend definierte Handler
   nicht still überschreiben.
3. In der HA-Entitätsverwaltung nur bei Bedarf beobachtete, eindeutig
   zuordenbare Transkriptionsvarianten als Alias des vorhandenen Geräts
   ergänzen. Den berechneten Namen beibehalten. Raumgruppen und
   unfreigegebene Geräte nicht zusätzlich exponieren. Der Projektorfarbpfad
   setzt die vorhandene Alias-Zuordnung `Projektor Hintergrund` zur
   HS-fähigen Entität `light.wohnzimmer_projektor_background` voraus.
   Der Master bleibt das Schaltziel; Lasersterne unterstützen nur Helligkeit.
4. Den vorhandenen STT-Quadlet-Dienst (Name und Port bleiben stabil) mit
   der in `profile.json` angegebenen Exec-Zeile betreiben. Der Parakeet-
   Modellordner muss unter dem vorhandenen gemounteten Modellcache liegen.
   Das getestete Wyoming-Image enthält Sherpa-ONNX; bei einem anderen Image
   muss die Backendverfügbarkeit geprüft werden. Kein zusätzlicher Dienst.
   Die vorherigen Whisper-Modelle bleiben als Rückfalloption erhalten.
5. In der bestehenden deutschen Assist-Pipeline die angegebenen STT-/TTS-
   und LLM-Optionen setzen. Der text-only Ollama-Alias verwendet dieselben
   Q3-Gewichte ohne Projektor sowie qwen3.5-Renderer und -Parser. Die
   lizenzierte Originalmodellquelle bzw. der gesicherte Blob bleibt maßgeblich;
   die Manifestreferenzen sind kein neuer Modelldownload. Kein LoRA-Adapter
   erforderlich. Den vorhandenen Systemprompt beibehalten und die additive
   Regel nur anfügen, wenn sie fehlt. Nicht den gesamten privaten
   HA-Config-Entry überschreiben. Die unter `ollama.server_cache` separat
   beobachteten drei Server-Umgebungsvariablen gehören in den bestehenden
   Ollama-Quadlet, nicht in die HA-LLM-Optionen. Die vorhandene persistente
   Ollama-Einbindung bleibt erhalten. Flash Attention und Q8-KV reduzieren
   den Speicherbedarf; `CUDA_CACHE_PATH` liegt unter dieser Einbindung,
   damit der CUDA-ComputeCache den Containerwechsel überlebt. Keine
   zusätzliche GPU-Residenz, kein zweiter Container und kein Modellwechsel.
   Den Cache bei Wiederherstellung aus dem passenden vorhandenen lokalen
   Bestand übernehmen oder von der Runtime neu erzeugen lassen; er ist
   regenerierbar und kein verpflichtendes Git-Artefakt. Bei inkompatiblem
   Treiber/Image nicht auf einen alten Cache vertrauen. Den bestehenden
   Keepalive-Wert nicht zur Kompensation eines leeren Caches erhöhen.
   Nur falls die drei Einstellungen tatsächlich abweichen, den Quadlet
   gezielt korrigieren, daemon-reload und einen koordinierten Neustart des
   Ollama-Dienstes durchführen; aktive Sprachdialoge/GPU-Arbeit abwarten.
6. YAML und Intent-Script-Schema mit der tatsächlich installierten
   HA-Runtime prüfen. Änderungen möglichst in einer einzigen HA-Aktivierung
   übernehmen, nicht während einer laufenden Sprachinteraktion. Nach
   STT-Änderungen ausschließlich den vorhandenen STT-Dienst neu starten.
   Bei Fehlern nur die eigenen Änderungen zurücknehmen, gesicherten
   Ursprungszustand wiederherstellen und den Dienst erneut prüfen.

## Abnahme

- Native Satzzuordnung in der installierten HA/Hassil-Version mit
  exponierten realen Namen bzw. Registry-Kopie prüfen. Für einzelne Lampen
  und Raumwünsche exakt Zielentitäten, Farbwerte und Prozent/Kelvin prüfen;
  keine zusätzlichen Hue-Raumgruppen. Musik aus muss den vorgesehenen
  Player stoppen. Negative/mehrdeutige Fälle dürfen keinen neu eingeführten
  Geräte- oder Musikbefehl auslösen. Projektor mit/ohne Raumzusatz auf
  Hintergrundlicht, Ein/Aus ausschließlich auf Master; andere Farbe auf
  einen um 120 Grad verschobenen Farbton bei vorhandenem HS-Wert. Falscher
  Raum, Negation und Mehrfachbefehl dürfen nicht in den neuen Pfad gelangen.
  Fehlende Entität muss als Fehler behandelt werden, nicht als Erfolg.
- STT über den existierenden Wyoming-Port prüfen (deutsche Sprache, klare
  Verneinung, ein realer Geräte-/Auftragsname und Stille). Die echten
  Mikrofon-/TTS-/Gerätewege separat abnehmen; Service-Health und Stubtests
  ersetzen sie nicht.
- Bei einer Ollama-Wiederherstellung die drei Cache-Variablen im laufenden
  Container, den persistenten Mount und die tatsächliche Kaltstartdauer
  prüfen. Der 25.11.2026 dokumentierte direkte synthetische Vergleich ergab
  mit wiederverwendetem CUDA-Cache 8,158 statt 74,769 Sekunden; die erste
  produktive direkte Modellprobe benötigte 10,190 statt zuvor 70,787 Sekunden.
  Q8-KV reduzierte den KV-Speicher von 1024 auf 544 MiB; kein Warm-Speedup
  nachgewiesen. Diese Messungen sind keine Garantie für reale Sprachdialoge.
- Frische HA-Erreichbarkeit, Satelliten-Reconnect, aktive Sprachdienste,
  tatsächliche Quell-/Runtime-Drift und den nächsten Restic-Snapshot prüfen.
  Vorhandene Modellcache-Dateien und private Konfigurationsdaten nicht
  als neue Git-Artefakte duplizieren.

Der bisherige Paket-Deploy darf bei der späteren Konsolidierung diese
Profilquelle berücksichtigen, ohne private Runtime-Dateien pauschal zu
überschreiben. Bis dahin bleibt die oben beschriebene selektive Anwendung
die Wiederherstellungsanleitung, keine automatische Rollout-Garantie.


## Synthetischer Routing-Eval

`python3 scripts/nabu_qwen_eval.py --check` zeigt die aktuellen Defaults
offline; `--smoke` bzw. `--run` verwendet Modell, Thinking, Kontext und
Keepalive aus diesem Profil sowie den öffentlichen Toolprompt und das Addendum.
Ein explizites `--model` wählt weiterhin einen Vergleichskandidaten.
Der Eval nutzt einen synthetischen Basisprompt, Temperatur 0 und keine
privaten HA-Prompts oder realen Geräte-Schemas. Er führt keine Werkzeuge aus.
Er ist deshalb ein reproduzierbarer Routingtest, **keine** Assist-Endabnahme.
Manifest und Summary binden Profil, Prompt und Optionen; alte Ergebnisse mit
8192 Kontext, Thinking aus und 190 Ausgabetokens bleiben historische
Vergleichsmessungen und sind nicht direkt mit dem neuen Profil vergleichbar.
