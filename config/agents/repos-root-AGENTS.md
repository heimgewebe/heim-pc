# Heimgewebe Repositories – Agenteneinstieg

Diese Datei gilt als gemeinsame Orientierung für Arbeiten unter `/home/alex/repos`.
Repository-eigene `AGENTS.md`-Dateien bleiben für die konkrete Arbeit vorrangig.

## Systemweite Orientierung

Konsultiere den kanonischen Systemkatalog unter `/home/alex/repos/systemkatalog`, wenn eine Frage:

- mehrere Repositories oder Systeme betrifft;
- Zweck oder Nicht-Zuständigkeit eines Systems klären muss;
- Wahrheitsbesitz, stabile Beziehungen oder Einstiegspunkte betrifft;
- eine systemweite Architekturannahme benötigt.

Nutze dafür bevorzugt die deterministische Leseoberfläche:

```bash
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py system <name>
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py truth-owner <domain>
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py relations <name>
```

Bei gewöhnlicher Codearbeit in nur einem Repository wird der Systemkatalog nicht pauschal geladen.

## Grenzen

- Der Systemkatalog beschreibt stabile Semantik; er ist kein Task-, PR-, CI- oder Runtime-Statussystem.
- Aktuelle Zustände müssen bei GitHub, CI, Bureau, Grabowski, systemd, Logs oder Healthchecks geprüft werden.
- Cabinet ist nur noch historische Bezeichnung und keine aktive Quelle.
- Private Inhalte, Credentials und lokale Agentenhistorien dürfen nicht aus dem Katalog abgeleitet oder veröffentlicht werden.
