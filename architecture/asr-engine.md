---
id: asr-engine
role: norm
status: canonical
last_reviewed: 2026-08-12
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - tests/test_asr_engine.py
---

# ASR Open Engine

## Zweck

`heim-pc` stellt eine lokale Transkriptionsoberfläche bereit, deren Standardpfad keine nutzungsabhängigen externen Kosten erzeugt. Der maschinenlesbare Vertrag liegt in `manifest/asr-engine-policy.v1.json`; dieses Dokument erklärt nur seine Bedien- und Architekturfolgen.

## Entscheidung

- **Default:** `Qwen/Qwen3-ASR-1.7B` über `qwen-asr==0.0.6` und den Transformers-Backendpfad.
- **Legacy-Vergleich:** `Systran/faster-whisper-large-v3` über `faster-whisper==1.2.1`.
- **Registriert, aber nicht automatisch ausführbar:** `nvidia/parakeet-tdt-0.6b-v3` und `OpenMOSS-Team/MOSS-Transcribe-Diarize`. Ein Modellname allein ist kein validierter Adapter. MOSS benötigt zusätzlich eine bewusste Bewertung seines Remote-Code-Pfads.
- **Gated/manual-only:** `CohereLabs/cohere-transcribe-03-2026`. Die Gewichte sind lokal nutzbar, aber der Download ist gated; die automatische Setup- und Inferenzoberfläche blockiert ihn deshalb.

Diese Auswahl gilt, solange der lokale repräsentative Benchmark keinen belastbaren Grund für einen Wechsel liefert. Ohne menschlich geprüften Referenztext darf Laufzeitmessung keine Qualitätsrangfolge begründen.

## Harte Invarianten

1. Inferenz erfolgt lokal. Pay-as-you-go-, Credit- oder metered API-Pfade gehören nicht zu dieser Oberfläche.
2. Nur `setup` darf Pakete oder offene Modellgewichte herunterladen. `doctor`, `transcribe` und `benchmark` laufen ohne Download; Inferenz setzt den Hugging-Face-Offline-Modus.
3. Jede Engine benötigt einen expliziten Adapter und eine positive Policy-Freigabe. Gated oder nur registrierte Engines scheitern vor Setup/Inferenz.
4. Audio, Referenztext und Transkript werden nicht in Git oder Benchmark-Evidenz kopiert.
5. `transcribe` gibt den Text ausschließlich auf stdout aus. `benchmark` gibt keinen Transkripttext aus und persistiert ihn nicht.
6. Benchmark-Evidenz unter `~/.local/state/heim-pc/asr-open-engine/` enthält nur technische Metadaten und nicht umkehrbare Digests. Sie bindet Git-HEAD, Dirty-State, Policy-Digest und den SHA-256 der ausführenden Adapterdatei. Mit `--reference` werden WER/CER im Speicher berechnet; gespeichert wird nur der Referenz-Digest samt Metriken.
7. Ein fehlgeschlagener echter Backendlauf erzeugt eine Fehler-Evidenz und beendet den Befehl nonzero. Es gibt keinen simulierten Erfolgs- oder Dry-Run-Pfad.

## Lokale Laufzeit

Pakete, Venvs und Modellcaches bleiben außerhalb von Git unter:

- `~/.local/cache/heim-pc/asr-open-engine/venv_qwen`
- `~/.local/cache/heim-pc/asr-open-engine/venv_faster-whisper`
- `~/.local/cache/heim-pc/asr-open-engine/hf_home`
- `~/.local/cache/heim-pc/asr-open-engine/fw_models`

Die Qwen-Referenzkonfiguration nutzt `Qwen3ASRModel.from_pretrained(...)`, `torch.bfloat16`, `cuda:0`, Batchgröße 1 und automatische Spracherkennung. Eingabemedien werden unmittelbar im Qwen-Kindprozess per lokalem `ffmpeg` in 16-kHz-Mono-Float-PCM im Speicher dekodiert und als `(numpy.ndarray, sample_rate)` übergeben; dadurch funktionieren auch Container wie MP4, ohne eine temporäre Audiodatei anzulegen. `doctor` prüft zusätzlich backend-spezifisch, dass PyTorch beziehungsweise CTranslate2 tatsächlich mindestens ein CUDA-Gerät sehen. FlashAttention oder vLLM sind keine Voraussetzung dieses Basispfads; sie können später nur nach eigener Messung ergänzt werden.

## Bedienung

```bash
# rein lesender Readiness-Check; lädt nichts herunter
./scripts/asr_engine.py doctor --engine qwen

# explizites, isoliertes Setup einschließlich offener Gewichte
./scripts/asr_engine.py setup --engine qwen

# echter lokaler Benchmark ohne Ausgabe/Persistenz des Transkripts
./scripts/asr_engine.py benchmark --audio /pfad/audio.m4a

# optional: Qualitätsmessung gegen einen lokalen Referenztext
./scripts/asr_engine.py benchmark --audio /pfad/audio.m4a --reference /pfad/referenz.txt

# bewusste Transkription auf stdout, ohne Persistenz
./scripts/asr_engine.py transcribe --audio /pfad/audio.m4a
```

Vor einer Änderung des Defaults sind reale deutsche Aufnahmen mit Referenztexten gegen mindestens einen passenden lokalen Vergleichskandidaten zu messen. Laufzeit, RTF, VRAM und WER/CER sind getrennte Achsen; Geschwindigkeit allein entscheidet nicht über Transkriptionsqualität.
