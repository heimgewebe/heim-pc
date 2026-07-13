---
id: home-entry
role: reality
status: canonical
last_reviewed: 2026-07-13
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
  - scripts/check_operator_entry.py
---

# Home-Entry Runtime Note

## Aktuelle Einordnung

`/home/alex` ist die lokale Landefläche für menschliche Arbeit, Terminal-Einstiege und Agentenstarts. Es ist kein versioniertes Vollabbild und kein kanonisches Inhaltsverzeichnis.

Der kanonische, maschinenlesbare lokale Einstieg liegt versioniert in `manifest/operator-entry.v1.json`. `scripts/install_operator_entry.py` projiziert ihn byteidentisch nach `~/.config/heimgewebe/operator-entry.v1.json` und installiert kurze Pointer als `/home/alex/AGENTS.md`, `/home/alex/repos/AGENTS.md` und `/home/alex/README.md`.

## Rollen

* ChatGPT über Grabowski ist der Operator für Prüfung und Ausführung.
* Der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen; er soll nicht als Shell-Ausführer dienen.
* Statische Dateien weisen auf Primärquellen. Sie behaupten keinen aktuellen Git-, PR-, CI-, Task- oder Runtime-Zustand.

## Kanonische Pointer-Form

Die lokale Projektion enthält nur:

* den Maschinenvertrag unter `~/.config/heimgewebe/operator-entry.v1.json`;
* den Pointer auf `~/repos/heim-pc` als Operatorium-Entrée;
* den Pointer auf `~/repos/systemkatalog` als kanonische Quelle stabiler Ökosystemsemantik;
* den Repositories-Pointer unter `/home/alex/repos/AGENTS.md`;
* die Regel, aktuelle Zustände frisch bei ihren Primärquellen zu lesen;
* die Grenze gegen breite Home-, Secret-, Browserprofil-, Keyring- und private Inhaltsscans.

Sie ist kein vollständiges Verzeichnis von `/home/alex`.

## Installation und Prüfung

```bash
python3 scripts/install_operator_entry.py                              # nur Plan, keine Mutation
python3 scripts/install_operator_entry.py --apply                      # nur ohne abweichende bestehende Pointer
python3 scripts/install_operator_entry.py --apply --replace-existing   # nach Prüfung des Plans
python3 scripts/check_operator_entry.py --require-installed
```

Der Installer sperrt parallele Installationen, prüft Zielpfade und Vorzustände, lehnt Symlinks ab und ersetzt abweichende bestehende Pointer nur mit `--replace-existing`. Vor dem atomaren Ersetzen werden Backups unter `~/.local/state/heim-pc/operator-entry-backups/` angelegt. Ein maschinenlesbarer Installationsbeleg liegt unter `~/.local/state/heim-pc/operator-entry-install-receipt.v1.json`. Der Checker verlangt bei `--require-installed` Bytegleichheit zwischen versionierter Quelle und allen lokalen Projektionen. Zusätzlich prüft er, dass der Installationsbeleg an den aktuellen Vertrags-Hash gebunden ist und die darin attestierten Zieldateien noch exakt übereinstimmen.

## Bekannte Grenzen

* Home-Dateien sind lokale Betriebsartefakte und nicht automatisch Teil dieses Repositories.
* Der Maschinenvertrag enthält absichtlich keine Live-Gesundheit, Taskpriorität, Branchstände oder Merge-Reife.
* Grabowskis Connector-Snapshot und die tatsächliche Befolgung des Vertrags müssen separat beobachtet werden.
* Der Systemkatalog bleibt zuständig für stabile Semantik; `heim-pc` hält nur lokale Lokatoren und Einstiegsketten.
* `state/index.json` und `state/repos.json` enthalten derzeit Placeholder-Daten und sind im Maschinenvertrag ausdrücklich als aktuelle Wahrheit ausgeschlossen.

## Sicherheitsgrenze

Ohne ausdrücklichen Auftrag und Zweckprüfung dürfen nicht gelesen oder ausgegeben werden:

* Credentials, Schlüssel, Tokens und Keyrings,
* Browserprofile und Sessiondaten,
* private Inhaltsverzeichnisse,
* Agent-Runtime-Historien,
* Roh-Snapshots und große lokale Dumps.

## Betriebslogik

1. lokal über `/home/alex/AGENTS.md`, `/home/alex/repos/AGENTS.md` oder den installierten JSON-Vertrag landen,
2. Grabowski-Laufzeit und Bootstrap frisch prüfen,
3. Auftrag als Einzelrepo-, systemweiten, Host-, Task- oder Historienfall klassifizieren,
4. nur die im Vertrag referenzierten Primärquellen lesen,
5. vor Mutation Repo-, PR-, CI-, Lease-, Worktree-, Task- und Prozesszustand prüfen,
6. genau einen begrenzten Effekt ausführen und Zielzustand erneut lesen.

Wenn diese Kette unterbrochen ist, ist das eine Entrée- oder Projektionsdrift, kein Grund für einen breiten Home-Scan.
