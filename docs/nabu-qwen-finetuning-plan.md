# Nabu: Qwen-Fine-Tuning und nachweisbare Modellverbesserung

**Stand:** 22. November 2026 · **Status:** Umsetzungsplan, kein Trainings- oder Rolloutnachweis  
**Owner:** heimgewebe/heim-pc · **Betrieb:** Heim-PC / Ollama / Home Assistant / Nabu  
**Grundsatz:** Verbesserungen an realen Nutzerwegen messen; bestehende produktive Modelle bis zur erfolgreichen Abnahme unverändert lassen.

## Ziel und Erfolgskriterium

Ein eigenes, auf Nabus deutsche Sprachdialoge, Werkzeugverträge und begründetes Entscheiden angepasstes **Qwen3-14B-Modell** als separat benanntes Ollama-Modell herstellen, ohne die derzeitigen Stärken des produktiven Assistenten zu verlieren. Ein Modellwechsel ist nur sinnvoll, wenn der Kandidat auf vorab fixierten, ungesehenen Nabu-Fällen **reproduzierbar besser** wird und keine kritischen Regressionen erzeugt. Ein hübscheres Antwortbeispiel, grünes Training oder ein bestandener Build reichen nicht.

Nicht Ziel: fortlaufend aktuelle Fakten, Systemzustände, persönliche Inhalte oder Zugangsdaten in Gewichte einprägen; unkontrolliertes Selbsttraining aus Nabus eigenen Ausgaben; Austausch funktionierender Quellen- und Werkzeugmechanismen; bezahlte Cloud-GPUs oder metered APIs ohne eigene Freigabe.

## Belegter Ausgangspunkt und technische Grenzen

- Der bestehende Nabu-Assist verwendet **`nabu-qwen3-14b-q6:20261121`** für schnelle lokale Klassifizierungsaufgaben; `nixos/system/nabu/llm.py` setzt hier `think=false`, `num_ctx=2048` und `temperature=0`. DeepAnswer verwendet separat **Qwen3.8 27B Q3_K_M** mit `num_ctx=8192` und `think=false`. Die tatsächlich eingerichtete HA-Conversation-Konfiguration vor einem Test erneut aus aktiver Runtime lesen.
- Historische Direktbenchmarks vom 21.11.2026: Qwen3-14B-Q6 erledigte 13/13 automatische Faktenmarker und 16/16 reguläre Werkzeugaufgaben, bei simulierten Folgedialogen 6/9 bis 9/9; Median für warme Aktionen ca. 0,68 s. Diese kleine Stichprobe belegt **keine** allgemein fehlerfreie Werkzeugfähigkeit. Quellen: Chronik-Eintrag `nabu-20261121-qwen-q6-mistral24-nextgen-decision`; bestehende Nabu-Tests unter `nixos/system/tests/test_nabu*.py`.
- 22.11.2026: Eine Qwen3.8-27B-Q4_K_M-gegen-Mistral-24B-Vergleichsprobe ergab keinen verlässlichen Qualitätsvorsprung von Qwen3.8 bei deutlich höherer Latenz. Deshalb **keine 27B-Trainingspriorität**. Quelle: Chronik `nabu-20261122-qwen38-27b-vs-mistral-deep`.
- Heim-PC: RTX 4070 Ti SUPER, 16 GiB VRAM, 64 GiB RAM. Die Unsloth-Tabelle nennt für QLoRA auf 14B **8,5 GiB als theoretisches Minimum**, auf 27B **22 GiB**. Kontextlänge, Optimizer, Aktivierungen, Hintergrundprozesse und Checkpoint-Konvertierung erhöhen den Bedarf. Vor Training tatsächliche freie VRAM-/RAM-/Disk-Ressourcen und CUDA-/Treiberkompatibilität messen.
- Die produktive Ollama-**Q6/GGUF-Datei ist kein geeigneter Ausgangscheckpoint für übliches QLoRA-Training**. Exakten zugehörigen Qwen3-14B-Hugging-Face-Checkpoint, Tokenizer, Chattemplate und Revision ermitteln und pinnen; Lizenz prüfen. Training und Inferenz dürfen keine stillschweigenden Modellvarianten mischen.
- Nabu-Quellcode und Tests sind versioniert; private HA-Konfiguration, Modellcaches, Trainingsbeispiele und Rohdialoge bleiben **außerhalb von Git**. Nabu-HA-Runtime ist nicht automatisch mit einem Git-Merge aktualisiert.

## Entscheidungsreihenfolge: erst nachweisen, dann Gewichte verändern

### A. Fehlerprofil und reproduzierbare Baseline

1. Im aktiven Nabu-Pfad die Modellidentitäten und `ollama show`-Metadaten, Chattemplate/Toolformat, Ollama-Version, VRAM-/Latenzwerte und HA-Toolvertrag lesen. Hauptmodell, Qwen-DeepAnswer und Mistral klar auseinanderhalten.
2. Vor weiteren Änderungen ein **blindes Testset** definieren, das der spätere Trainingslauf nicht sieht: zunächst mindestens 100 verschiedenartige Aufgaben, mit dialog- und templategetrennter Test-/Trainingsaufteilung. Reale, anonymisierte Fehlfälle haben Vorrang vor generischen synthetischen Prompts. Die Größe ist Pilotziel, keine Behauptung vorhandener Daten.
3. Testklassen: Musik (inkl. `media_id:null`), Browseraktionen und -grenzen, explizite Grabowski-Aufträge vs. Statusabfragen, Fragen ohne Werkzeug, Folgeaufträge/Anaphern, analytische Imperative, erforderliche aktuelle Quellen, Quellenunverfügbarkeit, JSON-/Tool-Schema-Gültigkeit, deutsche Sprachverständlichkeit und fehlertolerante Korrektur.
4. Erst reale Baseline gegen den bestehenden Q6-Tag und den aktiven HA-Toolvertrag messen. Ergebnis pro Fall speichern: Anfrageklasse, erwartete Aktion/Antwort, Modell-/Quellhash, tatsächliche Toolargumente, Erfolg/Fehler, Latenz, eventuelle gefährliche Fehlaktion, Bewertungsgrund und Beleg. Keine privaten Texte ins Repository.
5. **Stop-Regel:** Sind keine belastbaren Fehlercluster nachweisbar, kein Fine-Tuning starten. Zuerst vorhandene Tests, Tool-Schema, Prompt, Routing und Webquellen minimalinvasiv verbessern, wenn sie die eigentliche Ursache sind.

### B. Kuratierte Trainingsdaten

1. Aus bestätigten Fehlfällen und geprüften erfolgreichen Gegenbeispielen zunächst **200–500 hochwertige SFT-Beispiele** als Pilot-Zielgröße gewinnen, ohne die blinde Testmenge zu verwenden. Bei unzureichender Datenqualität Training vertagen.
2. JSONL-Datensätze mit Qwen-kompatiblen `system/user/assistant/tool`-Turns und **exakten Nabu-Toolnamen und Argumentverträgen** erzeugen. Positive, schwierige negative und korrekt nicht auszuführende Fälle aufnehmen; Mehrturn-Grenzen realistisch darstellen.
3. Jeder Datensatz enthält einen Herkunftsverweis, Klasse, Freigabestatus und eine maschinenprüfbare Erwartung. Persönliche Daten, Secrets, private Dialoge und echte Auth-Tokens weder in Trainingsdaten noch in Modellgewichte übernehmen. Öffentliche oder synthetische Beispiele sind entsprechend zu kennzeichnen.
4. Split nach **ursprünglichem Fall und Promptfamilie**, nicht zufällig nach nahezu identischen Zeilen; synthetische Varianten derselben Fallfamilie dürfen nicht in Train und Test zugleich landen.
5. Beispiele für wissenschaftliche Antwortdisziplin aufnehmen: Behauptung vs. Quelle, Beobachtung vs. Schlussfolgerung, Unsicherheit und Gegenargumente. Nicht Fakten ohne Quellennachweis als scheinbar dauerhaftes Wissen antrainieren.

### C. Lokaler QLoRA-Pilot

1. Trainingsumgebung **reproduzierbar und getrennt von Home Assistant/Ollama** vorbereiten, nicht reflexhaft eine neue permanente Service-Architektur bauen. Exakte Versionen von Qwen-Checkpoint, Unsloth, PyTorch, CUDA, Transformers und Dataset-Hashes festhalten.
2. Qwen3 14B mit **4-Bit-QLoRA + SFT** beginnen; als erste zu messende Hyperparameter beispielsweise LoRA-Rang 8/16, Batchgröße 1, Gradient Accumulation, Sequenzlänge 2048, begrenzte Schritte, kleine Validierung und Early Stopping. Das sind *Startversuche*, keine geprüften optimalen Werte. Speicherbedarf vorher mit kurzem Smoke und OOM-Abbruch prüfen.
3. Ausgaben und Werkzeugaufrufe entsprechend dem tatsächlichen Nabu-Modus trainieren (primär `think=false`); Fähigkeiten des Originalmodells für normale Sachfragen separat schützen. Thinking-/No-Thinking-Format nicht versehentlich vermischen.
4. Trainingsadapter, Metadaten, Logs, Checksums und sichere Rückfallkopie lokal außerhalb Git aufbewahren; Checkpoint- und Datenintegrität sowie Wiederherstellbarkeit prüfen. Training nur in einer GPU-Wartungsphase, damit Nabu weiterhin nutzbar bleibt.
5. Bei OOM, instabiler Loss-Kurve, Datenmängeln oder messbarem Forgetting abbrechen und zuerst den Pilotansatz ändern, statt automatisch größere Hardware oder immer neue Frameworks anzuschaffen.

### D. Export, Ollama-Kandidat und Vergleich

1. LoRA/QLoRA-Adapter mit dem **exakt passenden Originalcheckpoint** zusammenführen; Exportweg und Gewichtshashes dokumentieren.
2. Mit einer zur Architektur passenden, getesteten llama.cpp-Version in GGUF konvertieren und z. B. eine mit der bisherigen Q6-Klasse vergleichbare Quantisierung erzeugen. Chattemplate, Stop-Token, JSON-Format und Toolcalls unbedingt auf Kompatibilität testen. Quantisierung ist eine zusätzliche Qualitätsvariable: sowohl **gemergtes Modell vor Quantisierung** als auch **fertigen GGUF-Kandidaten** evaluieren.
3. Kandidaten ausschließlich unter neuem Tag, z. B. `nabu-qwen3-14b-tuned:pilot1`, via Ollama importieren. Produktivtag, HA-Modellverweis und bestehendes DeepAnswer/Mistral-Fallback bleiben zunächst unverändert.
4. Baseline und Kandidat auf identischer Hardware mit gleicher Kontextlänge, Temperatur, Tooldefinition und Prompt-/Runtime-Version vergleichen; jeweils Kaltstart, warme Antwort, VRAM und Fehlerfälle messen.
5. Außer direkter Ollama-Bewertung auch den **authentifizierten Home-Assistant-Conversation-Weg** mit tatsächlicher Toolausführung prüfen. Echte Mikrofon-/Lautsprecher-E2E-Prüfungen (MOTU) bleiben eigene Abnahme, sofern das Gerät nicht verbunden ist.

### E. Harte Auswahl und risikoarme Integration

Ein Kandidat darf nur übernommen werden, wenn **alle** folgenden Punkte belegt sind:

- Kein neuer kritischer False-Positive-Geräte-/Browser-/Grabowski-Eingriff, keine Regression bei Tool-Schemas oder Quellenpflichten.
- Auf dem vorab festgeschriebenen blinden Set mindestens das Niveau der Baseline in jeder kritischen Kategorie; auf dem nachgewiesenen Fehlercluster eine **vorab bestimmte relevante Verbesserung** (Pilotziel: mindestens 30 % weniger Fehler, sofern genügend Fehlfälle vorhanden; Fallzahl und Konfidenz berichten).
- Kein wesentlicher Qualitätsverlust bei generellen Fragen, deutschem Dialog oder Mehrturn-Aufgaben; manuelle Bewertung strittiger Fälle blind gegenüber Modellnamen.
- Sprachinteraktionslatenz und GPU-Speicherverbrauch bleiben im zuvor festgelegten betrieblich nutzbaren Budget. Als vorläufiger Grenzwert: warme Medianlatenz höchstens 20 % über Baseline, sofern der Qualitätsgewinn die Änderung rechtfertigt.
- Modellcheckpoint, Trainingsdatenversion (nur Hash/Provenienz), Adapter, Export, GGUF-Hash, Modelltag, Tests und Rollbackpfad sind nachvollziehbar.
- Änderung des produktiven HA-Modellverweises erst als **separater, kleiner PR/Rollout** mit Git-/CI-/Runtime-Readback und realem Nabu-Nutzerweg; bei schlechteren Ergebnissen sofort auf bestehenden Q6-Tag zurückstellen.

Erfüllt der Kandidat die Bedingungen nicht, bleibt er ein Experiment. Keine neue Modellversion auf bloßer Hoffnung produktiv setzen.

## Minimaler Umsetzungszuschnitt / Bureau

1. **Eval zuerst:** vorhandene Nabu-Testfälle und historische Benchmarks sichten, blindes Testset und Baseline mit reproduzierbarem Ergebnisbericht erstellen; frühere E2E-Arbeit nicht duplizieren.
2. **Ein lokaler Pilot:** nur bei belastbarem Fehlerprofil Trainingsdaten kuratieren und einen QLoRA-Adapter trainieren; keine gleichzeitigen 14B-/27B-/Mistral-Experimente.
3. **Gegenüberstellung:** unverändertes Q6 vs. angepasste Gewichte, mit denselben Fällen und Nutzungspfaden. Danach getrennte Entscheidung über einen produktiven Rollout.

Offene Implementierung als **ein** Bureau-Vorhaben behandeln, vorhandene Nabu-Tasks/PRs zuerst auf Überlappung prüfen und nicht als abgeschlossen verbuchen, nur weil dieser Plan im Repository liegt. Der bestehende Nabu-Conversation-/MOTU-Abnahmetask bleibt eigenständig.

## Referenzen (beim Ausführen frisch prüfen)

- Nabu: [`nixos/system/nabu/llm.py`](../nixos/system/nabu/llm.py), [`docs/nabu-music.md`](nabu-music.md), Tests in `nixos/system/tests/`.
- Qwen-QLoRA-Anleitung: https://github.com/QwenLM/Qwen3/blob/main/docs/source/training/unsloth.md
- Unsloth-Mindestbedarf: https://unsloth.ai/docs/get-started/fine-tuning-for-beginners/unsloth-requirements
- Ollama-GGUF-Import: https://github.com/ollama/ollama/blob/main/docs/import.mdx
- Historische Entscheidungen: Grabowski Chronik, `knowledge.ledger`, `nabu-20261121-qwen-q6-mistral24-nextgen-decision`, `nabu-20261122-qwen38-27b-vs-mistral-deep` und `nabu-pr433-20261122-captain-merge-main-production-verified`. Chronik ist **keine** aktuelle Runtime-Wahrheit.
