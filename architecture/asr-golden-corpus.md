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

Der Golden-Korpus liefert reproduzierbare, menschlich referenzierte Qualitätsdaten für lokale ASR-Engines. Er **ändert den ASR-Default niemals automatisch**. Der aktuelle Qualitätsdefault ist faster-whisper large-v3; der Korpus dient seiner breiteren Revalidierung und kann eine spätere reviewte Rollenänderung begründen.

Der Korpus selbst ist **privat und repo-extern**. In Git oder Bureau dürfen weder Audio, Referenztext, maschinelles Transkript noch private Dateipfade landen.

## Privates Manifest

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

`audio` und `reference` werden relativ zum privaten Manifest aufgelöst. Das Tool lehnt Manifest, Audio oder Referenz innerhalb des Heim-PC-Repositories ab. `reference_kind` muss `human-corrected` sein; ein maschinell erzeugtes Transkript ist keine Ground Truth.

## Qualitätsabdeckung

Die vollständige Golden-Revalidierung ist erst qualifiziert, wenn sie mindestens 20 Samples enthält und jede Kategorie mindestens einmal abdeckt:

- `clear_speech`
- `fast_or_quiet_speech`
- `background_noise`
- `proper_names_or_domain_terms`
- `multi_speaker`

Diese Schwelle ist ein **Voll-Audit-Gate**, kein Verbot einer expliziten, reviewten Operatorentscheidung. Ein Mensch kann die Policy nach eigener Evidenzbasis bewusst ändern; ein Benchmark darf das niemals selbst tun.

## Metrikvertrag v2

Jede lokale Engine erhält parallel zwei Qualitätsansichten:

- `wer` / `cer`: bisherige strict-v1-Semantik; Casefolding und Whitespace-Normalisierung, Interpunktion bleibt Bestandteil der Zeichen-/Wortdarstellung;
- `lexical_wer` / `lexical_cer`: punctuation-normalized-v2; reine Satzzeichenformatierung beeinflusst die Erkennungswertung nicht.

Für künftige Golden-Default-Reviews ist `mean_lexical_wer` die Auswahlmetrik. `mean_wer` bleibt erhalten, damit bestehende und neue Evidenz vergleichbar bleibt. Alte Receipts werden nicht nachträglich neu interpretiert.

Zusätzlich werden getrennt gemessen:

- Wall Time;
- RTF – Laufzeit relativ zur Audiodauer;
- beobachteter GPU-Speicherpeak.

Qualität hat Vorrang vor Geschwindigkeit. Parakeet kann deshalb trotz sehr guter Laufzeit/VRAM-Werte Speed-Pfad bleiben, ohne Qualitätsdefault zu sein.

## Persistierte Evidenz

`golden-benchmark` speichert ausschließlich:

- SHA-256 des privaten Gesamtmanifests;
- Audio- und Referenz-Digests;
- Kategorien;
- Engine-/Modell-/Adapter-/Git-/Policy-Identität;
- Metrik-Schemaversion;
- strict WER/CER und lexical WER/CER;
- RTF/Laufzeit/GPU-Metriken;
- aggregierte Mittelwerte.

Nicht gespeichert werden:

- Sample-ID;
- Dateiname oder Pfad;
- Referenztext;
- Transkripttext;
- API-Schlüssel.

Die Evidenz landet unter `~/.local/state/heim-pc/asr-open-engine/` und erhält Dateimodus `0600`.

## Bedienung

```bash
# Vertrag und Abdeckung prüfen
./scripts/asr_engine.py golden-check \
  --manifest /privater/pfad/golden.json

# Alle drei lokalen Rollen vergleichen
./scripts/asr_engine.py golden-benchmark \
  --manifest /privater/pfad/golden.json

# Qualitätsdefault gegen Fallback
./scripts/asr_engine.py golden-benchmark \
  --manifest /privater/pfad/golden.json \
  --engine faster-whisper \
  --engine qwen
```

Cloud-Ergebnisse gehören nicht in die automatische lokale Default-Auswahl und erfordern weiterhin eine getrennte explizite Kostenfreigabe.

## Default-Regel

Der aktuelle Default ist **faster-whisper large-v3**. Bei erfüllter 20-Sample-Abdeckung und vollständigen Messungen weist der Golden-Lauf sowohl den besten Kandidaten nach strict `mean_wer` als auch nach bevorzugtem `mean_lexical_wer` aus und setzt `eligible_for_default_review=true`. `automatic_default_change_allowed` bleibt immer `false`.

Ein tatsächlicher Defaultwechsel erfordert weiterhin eine separate reviewte Repository-Änderung. Genau so wurde der Wechsel zu faster-whisper am 2026-08-13 vorgenommen: als bewusste Operatorentscheidung, nicht als automatische Benchmarkmutation.
