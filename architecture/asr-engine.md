---
id: asr-engine
role: norm
status: canonical
last_reviewed: 2026-09-26
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - tests/test_asr_engine.py
  - tests/test_operator_entry.py
---

# ASR host integration

## Rolle dieses Repositories

`heim-pc` ist **nicht** mehr die semantische ASR-Autorität. Die kanonische
Capability `audio.transcribe` lebt in `heimgewebe/asr` mit Authority
`heimgewebe_asr_open_engine`.

Dieses Repository besitzt nur die Host-Seite:

- Capability-Locator und installierte Operator-Entry-Projektion;
- Beobachtung der lokalen Runtime;
- Migration und Kompatibilität von Cache/State;
- einen schmalen historischen Wrapper unter `scripts/asr_engine.py`.

Engine-Auswahl, Routing, Modellpins, Cloud-Kostenregeln, Transcript-Verträge,
Golden-Korpus und Benchmarksemantik dürfen hier nicht geforkt werden.

## Kanonische Host-Auflösung

Der Maschinenvertrag `manifest/operator-entry.v1.json` löst Audio-Transkription auf:

- Repository: `${HOME}/repos/asr`
- Einstieg: `python3 ${HOME}/repos/asr/scripts/asr_engine.py`
- Architektur: `${HOME}/repos/asr/architecture/asr-engine.md`
- Policy: `${HOME}/repos/asr/manifest/asr-engine-policy.v1.json`
- Transcript-Vertrag: `${HOME}/repos/asr/manifest/asr-transcript-contract.v1.json`
- Runbook: `${HOME}/repos/asr/runbooks/asr-local-transcription.md`
- Cache: `${HOME}/.local/cache/heimgewebe/asr`
- State: `${HOME}/.local/state/heimgewebe/asr`

Der Locator bleibt `capability_locator_only`. Er darf weder eine Engine pinnen
noch Cloud-/Metered-Nutzung autorisieren.

## Kompatibilitätswrapper

`scripts/asr_engine.py` enthält absichtlich keine ASR-Policy. Er führt nur den
kanonischen generischen Einstieg unter `${HOME}/repos/asr/scripts/asr_engine.py`
mit unveränderten Argumenten aus und scheitert, wenn dieser Einstieg fehlt.

Neue Consumer benutzen den generischen Einstieg direkt. Der Wrapper existiert
nur, damit historische Host-Aufrufer während der Migration nicht zu einer
zweiten Authority werden.

## One runtime, one cache

Historisch lagen Runtime und State unter:

- `~/.local/cache/heim-pc/asr-open-engine`
- `~/.local/state/heim-pc/asr-open-engine`

Zielzustand ist genau eine physische Runtime:

- `~/.local/cache/heimgewebe/asr`
- `~/.local/state/heimgewebe/asr`

Beim Cutover werden vorhandene Daten verschoben, nicht dupliziert. Historische
Pfade dürfen anschließend als Kompatibilitäts-Symlink auf den neuen Root
zeigen. `doctor` muss vor und nach der Migration nachweisen, dass keine
Neuinstallation oder zweite Modellkopie nötig ist.

## Verifikation

1. `${HOME}/repos/asr` steht auf dem gemergten kanonischen ASR-Main.
2. Der generische `doctor` ist grün.
3. Der Host-Capability-Resolver liefert `heimgewebe_asr_open_engine`.
4. Der historische Wrapper und der generische Einstieg führen auf dieselbe Runtime.
5. Eine reale lokale Transkription liefert `provider=local` und keine Cloud-Eskalation.
6. Kein ASR-Policy-/Transcript-/Golden-Vertrag verbleibt als zweite Wahrheit in `heim-pc`.
