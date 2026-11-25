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
  Lila/Hellgelb/Türkis und eindeutige Musik-Stopp-Befehle. Unbekannte Ziele, Fragen,
  Negationen und mehrdeutige Mehrfachbefehle bleiben beim normalen Fallback.
- `native_intent_scripts.yaml`: ausschließlich NabuStopMusic; die
  bestehende Music-Assistant-Entität `media_player.nabu_musik_motu`
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
   Den einzelnen NabuStopMusic-Block aus `native_intent_scripts.yaml`
   unter dem vorhandenen `intent_script:`-Mapping ergänzen, nicht die
   vollständige `configuration.yaml` ersetzen. Einen bereits abweichend
   definierten NabuStopMusic-Handler nicht still überschreiben.
3. In der HA-Entitätsverwaltung nur bei Bedarf beobachtete, eindeutig
   zuordenbare Transkriptionsvarianten als Alias des vorhandenen Geräts
   ergänzen. Den berechneten Namen beibehalten. Raumgruppen und
   unfreigegebene Geräte nicht zusätzlich exponieren.
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
   HA-Config-Entry überschreiben.
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
  Geräte- oder Musikbefehl auslösen.
- STT über den existierenden Wyoming-Port prüfen (deutsche Sprache, klare
  Verneinung, ein realer Geräte-/Auftragsname und Stille). Die echten
  Mikrofon-/TTS-/Gerätewege separat abnehmen; Service-Health und Stubtests
  ersetzen sie nicht.
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
