---
id: managed-builds
role: norm
status: canonical
last_reviewed: 2026-07-22
depends_on:
  - storage-lifecycle
  - operatorium-entry
  - security
verifies_with:
  - config/managed-build.v1.json
  - scripts/managed_build.py
  - scripts/managed_cargo_gc.py
  - tests/test_managed_build.py
  - tests/test_managed_cargo_gc.py
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
* Pro Identitätscache werden 10 GiB als Warn- und 20 GiB als Hartgrenze beobachtet.
* Für die Gesamtheit der verwalteten Cargo-Identitäten gilt zusätzlich eine bounded Retention: 50 GiB Maximalbudget, 30 GiB Zielbudget, mindestens sieben Tage unbenutzte Zeit, höchstens 20 GiB Reclaim und höchstens acht Identitäten pro Apply. Diese Werte steuern nur die Kandidatenauswahl und sind keine automatische Löschberechtigung.
* Überschreitet eine einzelne löschbare Identität das 20-GiB-Apply-Budget, wird sie nicht still verworfen und das Budget auch nicht automatisch überschritten: `plan` weist sie als `oversized_identity_requires_policy_override` mit dem minimal erforderlichen Budget aus. Erst eine explizite Policy-Änderung plus neuer Plan kann sie freigeben.

## Ablauf

1. `plan` liest Repository, Toolchain, Lockfiles, Profil und aktuelle Worktree-Ausgaben und erzeugt einen JSON-Plan ohne Verzeichnisse anzulegen.
2. `run --dry-run` entspricht dem Plan und liefert bei harter Sperre Exitcode 3.
3. `run` erzeugt ausschließlich die externen Cache-, Receipt- und Lifecycle-Lock-Verzeichnisse, setzt die Umgebung nur für den Kindprozess und führt ohne Shell aus. Für Cargo wird der exakte Cache-Key-Lockpfad im Binding-Receipt festgehalten.
4. Nach dem Kindprozess wird ein begrenztes Receipt mit Hashes, Pfaden, Rückgabecode und Vorher-/Nachher-Größe geschrieben. Die vollständige Kommandozeile wird nicht gespeichert.

## Cargo-Lifecycle und Garbage Collection

Der separate Einstieg `scripts/managed_cargo_gc.py` ergänzt den Buildpfad um einen kontrollierten Lebenszyklus. Er ist absichtlich nicht in `automatic_cleanup_authorized` aufgegangen.

1. `inventory` betrachtet ausschließlich direkte Kinder unter `${HOME}/.cache/heim-pc/managed-builds/cargo`.
2. Nur direkte, reale Verzeichnisse mit Namen aus exakt 64 hexadezimalen Zeichen gelten als verwaltete Identitätskandidaten. Benannte Alt-, Review- oder Sondertargets sowie direkte Symlink-/Nicht-Verzeichnis-Identitäten bleiben `unclassified` und werden nie inferiert gelöscht. Symlinks innerhalb eines echten Identity-Trees werden als Blätter inventarisiert und niemals verfolgt.
3. Lokale Managed-Build-, Binding- und Usage-Receipts liefern Repository-Provenienz und letzte Nutzung, soweit sie vorhanden sind. Fehlende historische Cargo-Provenienz wird nicht durch Dateialter ersetzt.
4. Eine externe Task-Autorität darf versionierte Schutz- und Nutzungsevidenz liefern. Für Operatorläufe ist das Grabowski. Unvollständige, intern hashinkonsistente oder fehlerhafte Evidenz blockiert die Kandidatenauswahl global; Grabowski bleibt alleinige Task-Wahrheit. `snapshot-evidence` kann eine vollständige Evidenz explizit als kleine lokale Usage-Receipts konservieren, damit die letzte Nutzungszeit älterer Caches auch nach späterer Task-Archivierung erhalten bleibt. Der Snapshot erteilt keine Löschberechtigung.
5. Ein unexpired Pin schützt jede Identität, deren Repository-Provenienz sicher demselben Repository zugeordnet ist. Ist die Repository-Provenienz historisch unbekannt und existiert irgendein aktiver Cargo-Pin, bleibt die Identität konservativ geschützt.
6. Ein lokaler `/proc`-Readback schützt zusätzlich exakte Managed-Cargo-Identitäten, auf die ein laufender Prozess über `CARGO_TARGET_DIR` zeigt. Nicht vollständig beobachtbare mögliche Cargo-/Rust-Buildprozesse blockieren Cleanup fail-closed; eindeutig fachfremde Prozesse tun das nicht.
7. Verwaltete Grabowski-Cargo-Läufe halten für ihre gesamte Prozesslaufzeit einen Shared-`flock` auf `${state_root}/cache-locks/cargo/<cache-key>.lock`. `apply` benötigt für dieselbe Identität einen exklusiven, nicht blockierenden Lock. Dadurch kann ein neu startender verwalteter Task nicht gleichzeitig mit der Löschung in denselben Cache schreiben; der `/proc`-Readback bleibt als zusätzliche Schranke für nicht kooperierende Prozesse bestehen.
8. Erst oberhalb des Cargo-Gesamtbudgets werden ausreichend alte, ungeschützte Identitäten nach belegten Bytes priorisiert. Pro Apply werden höchstens acht Kandidaten ausgewählt, damit die unmittelbar vor Wirkung wiederholten Prozessprüfungen bounded bleiben. Es gibt keinen Glob- oder Root-Wipe.
9. `plan` bindet Policy, lokale Usage-Receipts, den internen und externen Hash der Task-Evidenz, exakten Cache-Key, Pfad und einen strikten rekursiven Metadaten-Fingerprint in `plan_sha256`. Zusätzlich wird ein mtime-unabhängiger stabiler Tree-Fingerprint für Diagnose und Driftvergleich ausgegeben; er erteilt keine Löschfreigabe.
10. `apply` verlangt den exakten Plan-SHA und die wörtliche Bestätigung `apply-managed-cargo-gc`. Vor der ersten Wirkung werden Evidenz, Receipt-Stand, Kandidatenzahl und -bytes, eindeutige Cache-Keys, aufgelöste Pfadgrenze, Verzeichnistyp, Filesystem-/Mountgrenze und die strikten Tree-Fingerprints aller Kandidaten geprüft. Die exklusiven Cache-Key-Locks aller Kandidaten werden in deterministischer Reihenfolge vorab erworben und bis zum finalen Readback und Receipt gehalten.
11. Unmittelbar vor jedem symlink-sicheren `rmtree` werden Tree-Drift und `/proc` erneut geprüft. Gelöscht wird höchstens ein explizit geplanter 64-hex-Identity-Root pro Kandidat. Das Verschwinden wird unter Lock bestätigt. Tritt nach Beginn der Wirkung bei einem späteren Kandidaten ein Fehler auf, wird die bereits eingetretene Teilwirkung als `partial_failure` receipted, bevor `apply` fehlschlägt; eine teilweise Löschung darf nicht receiptlos bleiben.
12. Der abschließende Inventory-Readback und das GC-Receipt entstehen noch unter allen Kandidaten-Locks. Erst danach dürfen wartende verwaltete Builds die Identitäten wieder nutzen oder neu anlegen. Vor einem manuellen Apply muss die Grabowski-Evidenz unmittelbar neu projiziert und daraus ein neuer Plan erzeugt werden; ein älterer Evidenz- oder Plan-Hash ist keine Löschfreigabe.

Die reale Altlast von vor Einführung vollständiger Cargo-Nutzungsprovenienz ist damit bewusst fail-closed: Sie kann erst nach autoritativer Backfill-/Task-Evidenz oder expliziter gesonderter Klassifikation zu einem Löschkandidaten werden.

## Sicherheitsgrenzen

Der Managed-Build-Einstieg und der Cargo-Lifecycle:

* folgen bei Identitätsdateien und GC-Kandidaten keinen Symlinks; verschachtelte Symlinks im Payload werden als nicht verfolgte Blätter behandelt;
* akzeptieren nur bekannte Executables und Werkzeugzuordnungen;
* halten Cache und State unter `${HOME}` und außerhalb des Repositorys;
* lehnen Symlinks in neu zu erzeugenden Cache-/Lockpfaden sowie verschachtelte Mount- oder Filesystem-Grenzen innerhalb eines zu löschenden Identity-Trees ab;
* löschen keine Named-Legacy-, Worktree- oder unklassifizierten Daten;
* behandeln fehlende Task-Evidenz, unbekannte Provenienz und Drift als Schutzgrund;
* verleiht dem Kindprozess keine zusätzliche Ausführungsberechtigung;
* behaupten keine Buildkorrektheit und keine Task-, Queue- oder Claim-Wahrheit außerhalb Grabowskis.

## Alternativpfad

Für einmalige menschliche Diagnose bleibt der direkte interaktive Werkzeugaufruf zulässig. Er profitiert nicht automatisch von Externalisierung, Guard, Receipt oder Budgetbindung und darf deshalb nicht als verwalteter Operatorlauf ausgegeben werden.
