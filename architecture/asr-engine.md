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

Die Kosteninvarianten sind pfadbezogen: `default_path_zero_incremental_cost=true` und `default_path_local_inference_only=true` gelten für den Standardpfad. Metered Cloud bleibt ohne ausdrückliches Per-Run-Opt-in verboten; automatische Cloud-Eskalation bleibt ebenfalls verboten. Local-first bedeutet damit nicht local-only.

Maschinenlesbare Verträge:

- `manifest/asr-engine-policy.v1.json` – Engine-, Rollen-, Routing- und Kostenpolicy;
- `manifest/asr-transcript-contract.v1.json` – gemeinsames Transkriptergebnis;
- `manifest/asr-golden-corpus-contract.v1.json` – privater Qualitätsbenchmark.

## Optimale lokale Rollen

- **Qualitätsdefault:** `Systran/faster-whisper-large-v3` über `faster-whisper==1.2.1`.
- **Qualitätsfallback / zweite Meinung:** `Qwen/Qwen3-ASR-1.7B` über `qwen-asr==0.0.6`.
- **Speed-/Low-VRAM-Pfad:** `nvidia/parakeet-tdt-0.6b-v3`, revisionsgepinnt auf `541d1f99c6b0c3cd0b11a95167540bb8edefd82b`, über `transformers==5.15.0`.
- **Nicht automatisch ausführbar:** `OpenMOSS-Team/MOSS-Transcribe-Diarize` wegen des derzeitigen Remote-Code-Pfads.
- **Gated/manual-only:** `CohereLabs/cohere-transcribe-03-2026`.

Die Rollenwahl ist eine explizit reviewte Operatorentscheidung vom 2026-08-13. Grundlage waren drei menschlich referenzierte Vergleichsproben sowie eine zusätzliche längere Realaufnahme. Faster-whisper gewann alle diskriminierenden Referenzproben und war auf der längeren Probe qualitativ am kohärentesten. Der private 20-Sample-Golden-Korpus bleibt als breiteres Revalidierungsinstrument bestehen; er ist kein Mechanismus für automatische Policy-Mutationen.

Parakeet bleibt bewusst erhalten: Es bietet einen sehr schnellen, speichersparsamen lokalen Vergleichspfad. Seine geringere gemessene Qualität rechtfertigt jedoch keine Verwendung als Qualitätsdefault. Der aktuelle Adapter liefert keine verlässlichen Parakeet-Zeitstempel und keine eigene Spracherkennung; fehlende Eigenschaften werden nicht erfunden.

## Faster-whisper-Decoding

Der Qualitätsdefault verwendet:

```text
vad_filter=true
no_repeat_ngram_size=3
```

Die n-Gram-Bremse wurde nach einem real beobachteten Wiederholungsloop am Ende einer längeren Aufnahme gewählt. `condition_on_previous_text=false` wurde ebenfalls real geprüft, aber verworfen, weil dadurch im Mittelteil relevanter Gesprächsinhalt verloren ging. Die Optimierung begrenzt deshalb Wiederholungsloops, ohne den nützlichen vorherigen Textkontext pauschal abzuschalten.

## Routing

### `local-first`

Standard. Ohne explizite Engine läuft faster-whisper. Scheitert der Qualitätsdefault technisch, versucht der Router **lokal Qwen**, bevor irgendeine Cloud-Eskalation überhaupt in Betracht kommt.

```bash
./scripts/asr_engine.py route --audio /pfad/audio.m4a
```

Auch `transcribe --audio ...` ohne `--engine` benutzt diesen local-first-Pfad. Ein ausdrücklich gesetztes `--engine` bleibt dagegen ein exakter Einzelmodell-Aufruf und wird nicht still ersetzt.

### `dual-local`

Führt standardmäßig **faster-whisper + Qwen** auf derselben Aufnahme aus. Die Abweichungsrate ist ein Diagnose- und Eskalationssignal, kein Wahrheitsvotum. Der bestehende Schwellwert `0.18` bleibt unverändert, weil die bisherige Qualitätsstichprobe seine Neukalibrierung nicht trägt.

```bash
./scripts/asr_engine.py route \
  --strategy dual-local \
  --audio /pfad/audio.m4a \
  --json
```

Eine starke Abweichung setzt lediglich `cloud_recommended=true`. Sie löst **keinen** Cloud-Aufruf aus. Die persistierte Vergleichsevidenz enthält nur Digests und technische Identität, niemals Transkripttext oder privaten Dateipfad.

### Speed-/Low-VRAM-Pfad

Wenn Geschwindigkeit oder GPU-Speicher wichtiger als maximale Erkennungsqualität sind, kann Parakeet explizit gewählt werden:

```bash
./scripts/asr_engine.py transcribe --engine parakeet --audio /pfad/audio.m4a
```

Dieser Pfad ist absichtlich nicht der Default.

### Cloud-Eskalation

Registrierte optionale OpenAI-Modelle:

- `gpt-4o-transcribe`
- `gpt-4o-mini-transcribe`
- `gpt-4o-transcribe-diarize`

Cloud ist `metered`. Ein Aufruf benötigt pro Lauf eine bewusste Entscheidung. Bei Dual-Local-Eskalation sind beide Flags erforderlich:

```text
--escalate-to-cloud
--allow-metered-cloud
```

Ein expliziter `--strategy cloud` benötigt mindestens `--allow-metered-cloud`. Erst nach diesem Kosten-Gate wird `OPENAI_API_KEY` gelesen. API-Schlüssel werden nicht ausgegeben, in Git gespeichert oder in Benchmark-Evidenz übernommen.

## Gemeinsames Transkriptergebnis

Router-Ergebnisse normalisieren alle Backends auf `heim-pc.asr-transcript`. Faster-whisper liefert im aktuellen Adapter reale Segmentzeitstempel; Qwen und Parakeet lassen nicht verfügbare Segmentdaten leer.

```json
{
  "schema_version": 1,
  "kind": "heim-pc.asr-transcript",
  "provider": "local",
  "engine": "faster-whisper",
  "model": "Systran/faster-whisper-large-v3",
  "model_revision": null,
  "backend_version": "1.2.1",
  "text": "…",
  "language": "de",
  "segments": []
}
```

## Qualitätsmetriken

Die Evidenz ist bewusst versioniert:

- `wer` / `cer` behalten die bisherige **strict-v1**-Semantik mit Casefolding und Whitespace-Normalisierung. Alte Receipts werden dadurch nicht umgedeutet.
- `lexical_wer` / `lexical_cer` verwenden **punctuation-normalized-v2** und messen Erkennungsfehler ohne reine Interpunktionsformatierung.
- Künftige Golden-Default-Reviews verwenden `mean_lexical_wer` als Auswahlmetrik; strict WER/CER bleiben parallel als Vergleich erhalten.

Geschwindigkeit, RTF und VRAM bleiben Leistungsmetriken und dürfen eine Qualitätsentscheidung nicht allein bestimmen.

## Kosten- und Datenschutzinvarianten

1. `doctor`, `setup`, `transcribe` und `benchmark` bleiben lokale Engine-Oberflächen.
2. Lokale Inferenz setzt Hugging-Face/Transformers in den Offline-Modus.
3. Kein Routerpfad darf automatisch metered Cloud-ASR auslösen.
4. Cloud-Eskalation benötigt eine explizite per-run Kostenfreigabe.
5. Audio, Referenztext und Transkript werden nicht in Git oder Bureau kopiert.
6. Benchmark-Evidenz persistiert keinen Transkripttext.
7. Ein fehlgeschlagener Backendlauf scheitert nonzero; es gibt keinen simulierten Erfolgsweg.
8. Ein lokaler Defaultfehler darf im normalen local-first-Pfad auf Qwen zurückfallen, ohne Cloud oder externe Kosten auszulösen.

## Lokale Laufzeit

Pakete, Venvs und Modellcaches liegen außerhalb von Git unter `~/.local/cache/heim-pc/asr-open-engine/`. Qwen und Parakeet dekodieren Eingabemedien lokal mit `ffmpeg` nach 16-kHz-Mono-PCM im Speicher. `doctor` prüft Backend und CUDA, lädt aber nichts herunter.

## Bedienung

```bash
# Readiness des Qualitätsdefaults
./scripts/asr_engine.py doctor --engine faster-whisper

# Default: faster-whisper, mit lokalem Qwen-Fallback
./scripts/asr_engine.py transcribe --audio /pfad/audio.m4a

# Exakter Qwen-Lauf
./scripts/asr_engine.py transcribe --engine qwen --audio /pfad/audio.m4a

# Expliziter Speed-/Low-VRAM-Lauf
./scripts/asr_engine.py transcribe --engine parakeet --audio /pfad/audio.m4a

# Datenschutzsicherer Einzelbenchmark
./scripts/asr_engine.py benchmark --audio /pfad/audio.m4a --engine faster-whisper

# Strukturierter lokaler Router
./scripts/asr_engine.py route --audio /pfad/audio.m4a --json

# Qualitätsdefault gegen lokalen Fallback vergleichen
./scripts/asr_engine.py route --strategy dual-local --audio /pfad/audio.m4a --json
```

Der aktuelle Qualitätsdefault ist **faster-whisper large-v3**. Ein späterer Defaultwechsel bleibt eine explizit reviewte Änderung; weder Golden-Benchmark noch Router dürfen die Policy automatisch mutieren.
