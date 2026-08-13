---
id: asr-engine
role: norm
status: canonical
last_reviewed: 2026-08-13
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - tests/test_asr_engine.py
---

# ASR Open Engine

## Zweck

`heim-pc` stellt eine **local-first, benchmark-selected und optional cloud-escalatable** Transkriptionsoberfläche bereit. Der Normalfall bleibt lokale GPU-Inferenz ohne nutzungsabhängige externe Kosten. Cloud-ASR ist eine ausdrücklich kostenpflichtige Eskalationsoption und darf den lokalen Standardpfad weder still ersetzen noch automatisch auslösen.

Maschinenlesbare Verträge:

- `manifest/asr-engine-policy.v1.json` – Engine-, Routing- und Kostenpolicy;
- `manifest/asr-transcript-contract.v1.json` – gemeinsames Transkriptergebnis;
- `manifest/asr-golden-corpus-contract.v1.json` – privater Qualitätsbenchmark.

## Lokale Engines

- **Default:** `Qwen/Qwen3-ASR-1.7B` über `qwen-asr==0.0.6`.
- **Parakeet:** `nvidia/parakeet-tdt-0.6b-v3`, revisionsgepinnt auf `541d1f99c6b0c3cd0b11a95167540bb8edefd82b`, über `transformers_tdt_cuda` und `transformers==5.15.0`.
- **Vergleich:** `Systran/faster-whisper-large-v3` über `faster-whisper==1.2.1`.
- **Nicht automatisch ausführbar:** `OpenMOSS-Team/MOSS-Transcribe-Diarize` wegen des derzeitigen Remote-Code-Pfads.
- **Gated/manual-only:** `CohereLabs/cohere-transcribe-03-2026`.

Parakeet ist damit nicht mehr nur registriert, sondern besitzt einen realen automatischen Setup-/Inferenzadapter. Der aktuelle Adapter nutzt jedoch noch keine Parakeet-Zeitstempel; fehlende Fähigkeiten werden im gemeinsamen Ergebnisformat ausdrücklich leer gelassen und nicht erfunden.

## Routing

### `local-first`

Standard. Führt ausschließlich die primäre lokale Engine aus. Ohne Angabe ist das Qwen.

```bash
./scripts/asr_engine.py route --audio /pfad/audio.m4a
```

### `dual-local`

Führt zwei verschiedene lokale Engines auf derselben Aufnahme aus und berechnet aus den normalisierten Transkripten eine technische Abweichungsrate. Standardpaar ist Qwen + Parakeet.

```bash
./scripts/asr_engine.py route \
  --strategy dual-local \
  --audio /pfad/audio.m4a \
  --json
```

Eine starke Abweichung setzt lediglich `cloud_recommended=true`. Sie löst **keinen** Cloud-Aufruf aus. Der CLI-Lauf persistiert zusätzlich nur eine privacy-sichere Vergleichsevidenz mit Audio-/Transkript-Digests, Engine-/Revisionsidentität und Abweichungsmetrik; weder Transkripttext noch privater Dateipfad werden darin gespeichert.

### Cloud-Eskalation

Registrierte optionale OpenAI-Modelle:

- `gpt-4o-transcribe`
- `gpt-4o-mini-transcribe`
- `gpt-4o-transcribe-diarize`

Cloud ist `metered`. Ein Aufruf benötigt pro Lauf eine bewusste Entscheidung. Bei einer Dual-Local-Eskalation sind **beide** Flags erforderlich:

```text
--escalate-to-cloud
--allow-metered-cloud
```

Ein expliziter `--strategy cloud` benötigt mindestens `--allow-metered-cloud`. Erst nach diesem Kosten-Gate wird `OPENAI_API_KEY` gelesen; fehlt die Freigabe oder der Schlüssel, endet der Pfad vor dem Netzwerkzugriff. API-Schlüssel werden nicht ausgegeben, in Git gespeichert oder in Benchmark-Evidenz übernommen.

Die OpenAI-Adapter verwenden `POST /v1/audio/transcriptions`. Für das Diarization-Modell ist `diarized_json` registriert; `chunking_strategy=auto` wird mitgegeben.

## Gemeinsames Transkriptergebnis

Router-Ergebnisse normalisieren alle Backends auf `heim-pc.asr-transcript`:

```json
{
  "schema_version": 1,
  "kind": "heim-pc.asr-transcript",
  "provider": "local",
  "engine": "qwen",
  "model": "Qwen/Qwen3-ASR-1.7B",
  "model_revision": null,
  "backend_version": "0.0.6",
  "text": "…",
  "language": "German",
  "segments": []
}
```

Ein Segment enthält `start`, `end`, `speaker` und `text`. Nicht verfügbare Eigenschaften bleiben `null` beziehungsweise die Segmentliste bleibt leer. Der traditionelle Befehl `transcribe` bleibt kompatibel und gibt weiterhin nur Text auf stdout aus.

## Kosten- und Datenschutzinvarianten

1. `doctor`, `setup`, `transcribe` und `benchmark` bleiben lokale Engine-Oberflächen.
2. Lokale Inferenz setzt Hugging-Face/Transformers in den Offline-Modus.
3. Kein Routerpfad darf automatisch metered Cloud-ASR auslösen.
4. Cloud-Eskalation benötigt eine explizite per-run Kostenfreigabe.
5. Audio, Referenztext und Transkript werden nicht in Git oder Bureau kopiert.
6. Der normale Benchmark persistiert keinen Transkripttext.
7. Ein fehlgeschlagener Backendlauf scheitert nonzero; es gibt keinen simulierten Erfolgsweg.

## Lokale Laufzeit

Pakete, Venvs und Modellcaches liegen außerhalb von Git unter `~/.local/cache/heim-pc/asr-open-engine/`. Qwen und Parakeet dekodieren Eingabemedien lokal mit `ffmpeg` nach 16-kHz-Mono-PCM im Speicher. `doctor` prüft Backend und CUDA, lädt aber nichts herunter.

## Bedienung

```bash
# Nur Readiness prüfen
./scripts/asr_engine.py doctor --engine qwen

# Explizites lokales Setup
./scripts/asr_engine.py setup --engine parakeet

# Traditionelle lokale Textausgabe
./scripts/asr_engine.py transcribe --audio /pfad/audio.m4a

# Datenschutzsicherer Einzelbenchmark
./scripts/asr_engine.py benchmark --audio /pfad/audio.m4a --engine parakeet

# Strukturierter lokaler Router
./scripts/asr_engine.py route --audio /pfad/audio.m4a --json

# Zwei lokale Modelle vergleichen, ohne Cloud
./scripts/asr_engine.py route --strategy dual-local --audio /pfad/audio.m4a --json
```

Für Qualitätsentscheidungen gilt ausschließlich der private Golden-Korpus aus `architecture/asr-golden-corpus.md`. Geschwindigkeit, RTF und VRAM dürfen eine WER/CER-Entscheidung nicht ersetzen. **Qwen bleibt Default**, bis ausreichend menschlich korrigierte Referenzevidenz einen Review eines anderen lokalen Defaults rechtfertigt.
