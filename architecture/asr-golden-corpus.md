---
id: asr-golden-corpus
role: norm
status: canonical
last_reviewed: 2026-08-13
depends_on:
  - asr-engine
verifies_with:
  - tests/test_asr_engine.py
---

# Privater ASR-Golden-Korpus

## Zweck

Der Golden-Korpus entscheidet nicht automatisch über einen ASR-Default. Er liefert reproduzierbare, menschlich referenzierte Qualitätsdaten, auf deren Grundlage ein späterer Review Qwen, Parakeet oder faster-whisper vergleichen kann.

Der Korpus selbst ist **privat und repo-extern**. In Git oder Bureau dürfen weder Audio, Referenztext, maschinelles Transkript noch private Dateipfade landen.

## Privates Manifest

Das Manifest liegt außerhalb des Repositories, beispielsweise unter einem privaten lokalen Datenpfad. Beispiel:

```json
{
  "schema_version": 1,
  "kind": "heim-pc.asr-golden-corpus",
  "items": [
    {
      "id": "de-001",
      "categories": ["clear_speech", "proper_names_or_domain_terms"],
      "audio": "audio/de-001.m4a",
      "reference": "references/de-001.txt",
      "reference_kind": "human-corrected"
    }
  ]
}
```

`audio` und `reference` werden relativ zum privaten Manifest aufgelöst. Das Tool lehnt Manifest, Audio oder Referenz innerhalb des Heim-PC-Repositories ab. `reference_kind` muss `human-corrected` sein; ein maschinell erzeugtes Transkript ist keine zulässige Ground Truth.

## Qualitätsabdeckung

Ein Korpus ist erst für einen Default-Review qualifiziert, wenn er mindestens 20 Samples enthält und jede der folgenden Kategorien mindestens einmal abdeckt:

- `clear_speech`
- `fast_or_quiet_speech`
- `background_noise`
- `proper_names_or_domain_terms`
- `multi_speaker`

Diese Schwelle ist eine Mindestanforderung, kein Beweis statistischer Allgemeingültigkeit.

## Metriken

Für jedes lokale Modell werden getrennt gemessen:

- WER – Word Error Rate gegen den menschlich korrigierten Referenztext;
- CER – Character Error Rate;
- Wall Time;
- RTF – Laufzeit relativ zur Audiodauer;
- beobachteter GPU-Speicherpeak.

WER/CER sind Qualitätsmetriken. RTF/Laufzeit/VRAM sind Leistungsmetriken. Eine schnellere Engine darf nicht allein deshalb zum Qualitätsdefault werden.

## Persistierte Evidenz

`golden-benchmark` speichert ausschließlich:

- SHA-256 des privaten Gesamtmanifests;
- Audio- und Referenz-Digests;
- Kategorien;
- Engine-/Modell-/Adapter-/Git-/Policy-Identität;
- WER/CER/RTF/Laufzeit/GPU-Metriken;
- aggregierte Mittelwerte.

Nicht gespeichert werden:

- Sample-ID;
- Dateiname oder Pfad;
- Referenztext;
- Transkripttext;
- API-Schlüssel.

Die Evidenz landet wie der bestehende Einzelbenchmark unter `~/.local/state/heim-pc/asr-open-engine/` und erhält Dateimodus 0600.

## Bedienung

```bash
# Nur privaten Manifestvertrag und Abdeckung prüfen
./scripts/asr_engine.py golden-check \
  --manifest /privater/pfad/golden.json

# Alle drei lokalen Engines vergleichen
./scripts/asr_engine.py golden-benchmark \
  --manifest /privater/pfad/golden.json

# Explizite Teilmenge
./scripts/asr_engine.py golden-benchmark \
  --manifest /privater/pfad/golden.json \
  --engine qwen \
  --engine parakeet
```

Der Golden-Benchmark akzeptiert ausschließlich lokale Engines. Cloud-Ergebnisse können über getrennte, explizit freigegebene Transkriptionsläufe untersucht werden, gehören aber nicht in die automatische lokale Default-Auswahl.

## Default-Regel

Der aktuelle Default bleibt Qwen. Selbst ein vollständiger Golden-Lauf ändert keine Policy-Datei. Bei erfüllter Mindestabdeckung wird lediglich `eligible_for_default_review=true` und der beste lokale Kandidat nach mittlerer WER ausgewiesen. Ein tatsächlicher Default-Wechsel erfordert eine separate reviewte Repository-Änderung.
