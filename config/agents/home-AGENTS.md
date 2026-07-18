# Heim-PC – kanonischer Operator-Einstieg

Diese Datei ist ein lokaler Pointer. Die versionierte Wahrheit liegt in `~/repos/heim-pc`.

## Maschinenvertrag

Lies zuerst:

1. `~/.config/heimgewebe/operator-entry.v1.json`
2. `~/repos/heim-pc/AGENTS.md`
3. bei systemweiten Fragen `~/repos/systemkatalog/AGENTS.md`

Für ChatGPT über Grabowski beginnt der Live-Check mit `grabowski_status(view="evidence")`, `grabowski_agent_bootstrap()` und `grabowski_context(profile="concise")`.

## Rollen

- ChatGPT über Grabowski ist der Operator für Prüfung und Ausführung.
- Der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen; er soll nicht als Shell-Ausführer benutzt werden.
- Statische Dateien sind Wegweiser. Aktueller Zustand kommt nur aus Git, GitHub, CI, Bureau, Grabowski, systemd, Logs und Healthchecks.

## Kostenregel

- Externe KI- und API-Nutzung muss ohne zusätzliche oder nutzungsabhängige Kosten bleiben.
- Nur kostenlose Kontingente, lokale Modelle und bestehende Flatrates ohne Mehrverbrauchskosten verwenden.
- Kein Pay-as-you-go, kein Credit-Kauf, kein Auto-Top-up, kein Abonnement-Upgrade und kein metered API key.
- Unklarer Billingstatus bedeutet Stop vor der ersten Inferenz; ein Budget über 0 USD braucht eine neue ausdrückliche Freigabe.

## Grenzen

- Kein breiter Scan von `/home/alex`.
- Keine Secret-, Browserprofil-, Keyring-, private Inhalts- oder Agentenverlaufsflächen ohne ausdrücklichen Zweck und passende Autorität lesen.
- Fremde Dirty-States, Worktrees, Leases, Prozesse, Branches und laufende Arbeiten nicht verändern.
- Vor jeder Mutation Ziel, erwartetes Ergebnis, Validierung, Stop-Kriterium und Recovery bestimmen; danach Zielzustand erneut lesen.
