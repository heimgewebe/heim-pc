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
Dieses Dokument beschreibt die Richtlinien und Infrastruktur für das lokale, zero-incremental-cost ASR-System (Automatic Speech Recognition) innerhalb der heim-pc Umgebung.

## Richtlinien
1. **Zero-Cost Invariant**: Die Inferenz muss lokal erfolgen und darf keine nutzungsabhängigen (metered) Kosten verursachen.
2. **Standard-Engine**: Qwen3-ASR-1.7B ist der deterministische, ungated Default.
3. **Erlaubte Fallbacks**: Parakeet v3, MOSS Transcribe-Diarize und faster-whisper.
4. **Cloud/Gated Modelle**: Modelle wie Cohere Transcribe werden explizit als "gated" markiert. Die automatisierte Ausführung/Inferenz über diese Engines ist durch die CLI strikt blockiert.
5. **Datenschutz**:
   - Audio und Transkripte werden niemals im Git-Repository persistiert.
   - Es werden nur Metadaten ("privacy-safe evidence") lokal in `~/.local/state/heim-pc/asr-open-engine` protokolliert.
   - Referenztexte selbst werden nicht gespeichert. Ohne Referenz kann die CLI keine Qualität (WER/CER) behaupten.

## Architektur
Das System besteht aus:
- **Policy**: Die Konfiguration liegt maschinenlesbar unter `manifest/asr-engine-policy.v1.json`.
- **CLI**: Die Werkzeuge für Benchmarking und Systemstatus (`doctor`) sind in `scripts/asr_engine.py` implementiert. Der `doctor`-Befehl lädt keine Gewichte herunter.
- **Evidenz**: Jeder Benchmark speichert lediglich Metadaten wie den Input-Digest, die Laufzeit, die verwendete Engine und optional Metriken (sofern eine Metrik-Berechnung ohne Speicherung des Referenztextes durchführbar ist).

## Laufzeit
Um einen Benchmark durchzuführen, muss die Audio-Datei explizit angegeben werden:
```bash
./scripts/asr_engine.py benchmark --audio /pfad/zur/datei.mp4
```
