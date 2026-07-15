---
id: managed-builds
role: norm
status: canonical
last_reviewed: 2026-07-15
depends_on:
  - storage-lifecycle
  - operatorium-entry
  - security
verifies_with:
  - config/managed-build.v1.json
  - scripts/managed_build.py
  - tests/test_managed_build.py
---

# Verwaltete Buildausgaben

## Zweck

Automatisierte Operatorläufe dürfen große regenerierbare Buildausgaben nicht unkontrolliert in temporären Worktrees vervielfachen. Der kanonische Einstieg ist:

```text
python3 ${HOME}/repos/heim-pc/scripts/managed_build.py
```

Der Vertrag gilt ausschließlich für ausdrücklich verwaltete Läufe über diesen Einstieg. Direkte interaktive Aufrufe durch den Menschen werden weder über Shellprofile noch über globale Umgebungsvariablen verändert.

## Identität

Jeder externe Cachepfad ist an folgende Eingaben gebunden:

1. gemeinsame Git-Repository-Identität statt einzelner Worktree-Pfad;
2. Werkzeugklasse;
3. beobachtete Toolchain-Identität;
4. Hash der vorhandenen Lock- und Manifestdateien;
5. Buildprofil.

Ändert sich eine Eingabe, entsteht ein anderer Cache-Key. Ein alter Cache wird dadurch nicht als passend behauptet.

## Werkzeugklassen

| Klasse | Externe Pfade | Lokal verbleibende, überwachte Projektion |
|---|---|---|
| Cargo | `CARGO_TARGET_DIR` | `target/` |
| Node | npm-, Yarn- und pnpm-Cache/Store | `node_modules/`, `.yarn/`, `.npm/`, `dist/`, `build/` |
| Python | pip-, uv- und Bytecode-Cache | `.venv/`, `venv/`, `__pycache__/`, Test-/Lint-Caches, `dist/`, `build/` |
| Playwright | Browserpakete plus Node-Caches | `test-results/`, `playwright-report/`, `blob-report/` |

Node- und Python-Projektionsverzeichnisse werden nicht blind umgebogen, weil deren Verzeichnissemantik werkzeug- und projektspezifisch ist. Stattdessen werden die wiederverwendbaren Stores externalisiert und die lokalen Projektionen budgetiert.

## Budgets und Sperre

* Ab 2 GiB lokaler regenerierbarer Projektion meldet der Guard `warning`.
* Ab 5 GiB meldet er `hard_limit` und blockiert einen neuen verwalteten Lauf.
* Eine Ausnahme benötigt einen begründeten, werkzeug- und repositorygebundenen Pin mit Ablaufzeit von höchstens sieben Tagen.
* Pins erteilen keine Lösch-, Merge- oder Ausführungsberechtigung.
* Pro Identitätscache werden 10 GiB als Warn- und 20 GiB als Hartgrenze beobachtet. Die Hartgrenze ist zunächst ein Sichtbarkeitsbefund; kontrollierte Retention folgt in T006.

## Ablauf

1. `plan` liest Repository, Toolchain, Lockfiles, Profil und aktuelle Worktree-Ausgaben und erzeugt einen JSON-Plan ohne Verzeichnisse anzulegen.
2. `run --dry-run` entspricht dem Plan und liefert bei harter Sperre Exitcode 3.
3. `run` erzeugt ausschließlich die externen Cache- und Receipt-Verzeichnisse, setzt die Umgebung nur für den Kindprozess und führt ohne Shell aus.
4. Nach dem Kindprozess wird ein begrenztes Receipt mit Hashes, Pfaden, Rückgabecode und Vorher-/Nachher-Größe geschrieben. Die vollständige Kommandozeile wird nicht gespeichert.

## Sicherheitsgrenzen

Der Managed-Build-Einstieg:

* folgt bei Identitätsdateien keinen Symlinks;
* akzeptiert nur bekannte Executables und Werkzeugzuordnungen;
* hält Cache und State unter `${HOME}` und außerhalb des Repositorys;
* lehnt Symlinks in neu zu erzeugenden Cachepfaden ab;
* löscht keine Build-, Cache- oder Worktree-Daten;
* verleiht dem Kindprozess keine zusätzliche Ausführungsberechtigung;
* behauptet keine Buildkorrektheit.

## Alternativpfad

Für einmalige menschliche Diagnose bleibt der direkte interaktive Werkzeugaufruf zulässig. Er profitiert nicht automatisch von Externalisierung, Guard, Receipt oder Budgetbindung und darf deshalb nicht als verwalteter Operatorlauf ausgegeben werden.
