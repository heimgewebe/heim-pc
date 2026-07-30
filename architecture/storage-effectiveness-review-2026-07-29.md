# Speicher-Wirksamkeitsprüfung: Abschluss vom 30. Juli 2026

## Urteil

> **Abschlussgate erfüllt:** Das Mindestfenster von 14 vollständigen Tagen endete `2026-07-29T21:13:26.256171Z`. Das gebundene Endinventar entstand um `2026-07-30T03:41:06.194320Z`, also 6 Stunden, 27 Minuten und 39,938149 Sekunden nach dem Gate. Das Beobachtungsfenster umfasst damit 14 Tage, 6 Stunden, 27 Minuten und 39,938149 Sekunden. `STORAGE-LIFECYCLE-V1-T009` darf auf dieser Evidenz terminalisiert und der PR nach aktuellen Head-, Review- und CI-Prüfungen gemergt werden.

- **Schwellen bleiben unverändert.** Die Messwerte rechtfertigen keine Lockerung; drei Produzenten liegen weiterhin über ihren Hard-Limits.
- **Die Worktree-Bereinigung wirkt, begrenzt den Zufluss aber noch nicht ausreichend.** 361,13 GiB revisionsgebundene Rückgewinnung senkten den gemessenen Worktree-Bestand netto um 20,19 GiB; der Endbestand bleibt dennoch über dem Hard-Limit.
- **Der Cache ist der dominante offene Befund.** `user-cache` wuchs im Fenster um 181,69 GiB; innerhalb des Fensters liegt kein Cache-Cleanup-Receipt vor.
- **Die globale Ausnahme bleibt ausdrücklich aktiv.** Temporäre plus regenerierbare Daten überschreiten das globale Hard-Budget um 236,00 GiB. Das ist ein Befund, keine Löschfreigabe.
- **Prävention und Recovery sind belegt, aber nicht gleichbedeutend mit Budgeteinhaltung.** Inventar und Timer erkennen Überschreitungen; Worktree-Receipts belegen Rückgewinnung im Fenster, der Cache-Receipt nur den Zustand unmittelbar vor der Baseline.

## Evidenzbindung

- Beobachtungsfenster: `2026-07-15T21:13:26.256171Z` bis `2026-07-30T03:41:06.194320Z` (14 Tage, 6 Stunden, 27 Minuten und 39,938149 Sekunden).
- Baseline: `/home/alex/.local/state/heim-pc/storage-remediation/STORAGE-LIFECYCLE-V1-T008/storage-inventory-final.json`, Datei-SHA-256 `10dbc82106e450500b158c8261eded5cbd0f8f9a15ec215e32b06cc31b17afdd`, Inventar-SHA-256 `c3b2a14b0a7108dc3434476e75843cb76c47bb4127923f0988c79c899ef00324`.
- Endinventar: `/home/alex/.local/state/heim-pc/storage-remediation/STORAGE-LIFECYCLE-V1-T009/storage-inventory-post-gate.json`, frisch mit Skript und Richtlinie aus dem exakten PR-Head `174b782808b3e2fdce30aa6e85b68dacc79bfdff` erzeugt, Datei-SHA-256 `ec1e00b6152075c3b2545547321e384e1a127eed38f489213dc77ba55b087d4b`, Inventar-SHA-256 `0b2e9db1e97cc33133c7a3df1b066f14e1f78b867b41f54300ffe171b7553d55`.
- Richtlinie: `config/storage-lifecycle.v1.json`, Datei-SHA-256 `5f9ee22e12a771059bac9b9550f54b99fa1f9b3ca9ce9d982f9645890c7816c7`.
- Zwischenzeitliche Bestandsverläufe werden nicht erfunden: Es liegen zwei vollständige Inventare und dazwischen hashgebundene Cleanup-Receipts vor. Der genaue Tagesverlauf innerhalb des Fensters bleibt unbekannt.

## Produzenten

| Produzent | Klasse | Start | Ende | Delta | Startstatus | Endstatus | Hard-Limit |
|---|---:|---:|---:|---:|---|---|---:|
| `repo-worktrees` | `temporary_workspace` | 171.11 GiB | 150.91 GiB | -20.19 GiB | `hard_limit` | `hard_limit` | 120.00 GiB |
| `repobrief-auto` | `temporary_workspace` | 1.13 GiB | 1.13 GiB | +0.00 GiB | `ok` | `ok` | 40.00 GiB |
| `user-cache` | `regenerable_cache` | 52.17 GiB | 233.86 GiB | +181.69 GiB | `hard_limit` | `hard_limit` | 50.00 GiB |
| `trash` | `temporary_workspace` | 21.22 GiB | 0.11 GiB | -21.11 GiB | `hard_limit` | `ok` | 20.00 GiB |
| `grabowski-releases` | `durable_evidence` | 10.12 GiB | 20.29 GiB | +10.17 GiB | `warning` | `hard_limit` | 20.00 GiB |
| `vm-data` | `canonical` | 15.17 GiB | 15.17 GiB | +0.00 GiB | `ok` | `ok` | 100.00 GiB |

## Klassen und globales Budget

| Klasse | Start | Ende | Delta |
|---|---:|---:|---:|
| `canonical` | 15.17 GiB | 15.17 GiB | +0.00 GiB |
| `durable_evidence` | 10.12 GiB | 20.29 GiB | +10.17 GiB |
| `regenerable_cache` | 52.17 GiB | 233.86 GiB | +181.69 GiB |
| `temporary_workspace` | 193.46 GiB | 152.15 GiB | -41.31 GiB |

- Temporär plus regenerierbar: 245.63 GiB → 386.00 GiB.
- Globales Warnbudget: 100.00 GiB; globales Hard-Budget: 150.00 GiB.
- Explizite Ausnahme am Ende: 236.00 GiB über dem Hard-Budget. Sie autorisiert keine Löschung.
- Dateisystembelegung: 31.46% → 56.28%; der globale Dateisystemstatus bleibt `ok`.

## Rückgewinnung im Fenster

- Worktree-Target-Maintenance: 15 Receipts, 45 entfernte Targets, 361.13 GiB belegte Blöcke entfernt.
- Daraus folgt für `repo-worktrees` ein Bruttozufluss von mindestens 340.94 GiB: entfernte Bytes abzüglich des negativen Nettodeltas. Die Rückgewinnung überstieg diesen Mindestzufluss um 20.19 GiB; der Bestand sank, blieb aber über dem Hard-Limit.
- Für `user-cache` liegt innerhalb des Beobachtungsfensters kein Cleanup-Receipt vor; eine Cache-Rückgewinnung im Fenster wird daher nicht behauptet.

### Worktree-Receipts

| Abschluss (UTC) | Receipt-SHA-256 | Targets | Entfernt | Ergebnis |
|---|---|---:|---:|---|
| `2026-07-22T17:57:17Z` | `575358c8ba92fbf8f96431dd666338b2a246ff8f271144804958f06f5a7d6a37` | 8 | 27.05 GiB | `removed` |
| `2026-07-22T23:58:53Z` | `cab9e5b44f709e53ff175e05d681e73a91c8e3f54809dca549d017a86f1d6861` | 8 | 39.72 GiB | `removed` |
| `2026-07-23T06:11:37Z` | `a5d711c759bfda93e5f286058025d81ccd58d5429ac8707db7358221a26a6eb4` | 6 | 61.65 GiB | `removed` |
| `2026-07-23T12:21:13Z` | `ba25c047db0b16197461a1484d5acb5b16d71b2541afd26012ec00d012730e81` | 3 | 49.33 GiB | `removed` |
| `2026-07-23T18:26:47Z` | `bb62fa2853818258df685d955e2e2fe71cf24d789936498ec1c7d69fe92cd752` | 4 | 29.75 GiB | `removed` |
| `2026-07-24T12:58:33Z` | `5b656e0b43e7a0640207078496b9894894369f8f7bdb220e2a3d97cd042aa5e6` | 2 | 12.41 GiB | `removed` |
| `2026-07-24T19:13:08Z` | `2d055ba8ccf577d3ae7fe7d4a9a3c004f84e36ee556c5d7deb575da1a6177f64` | 3 | 20.15 GiB | `removed` |
| `2026-07-25T13:31:10Z` | `b2214024d11dd61253a81f68c26be3b7ac8b6bc50762b3ded5d62ab947d86a72` | 2 | 23.06 GiB | `removed` |
| `2026-07-25T19:40:52Z` | `b6cfbc1524c0fd9a6062095adc82edb4461c73a959da0114ab39d3489f4f9a5e` | 1 | 11.50 GiB | `removed` |
| `2026-07-27T12:09:29Z` | `8ed532ee14d179e4e2d68e5e426ff8fe161030429cfd7100e33fe8e19ac7ae26` | 1 | 11.39 GiB | `removed` |
| `2026-07-29T02:00:13Z` | `c79c4c64000ce01c95412330e2717635ac0f26a0d354494622a2015968657989` | 1 | 12.74 GiB | `removed` |
| `2026-07-29T08:00:21Z` | `ca3756c48ca01b34c2940191cf88eb13adc30ea6dd672ebf833c14f5dfb11151` | 2 | 9.74 GiB | `removed` |
| `2026-07-29T14:09:45Z` | `c65af18e7c97fba37faedccbe6eddfd9fdfb48516542c4f36fe754a3f06b8355` | 1 | 4.33 GiB | `removed` |
| `2026-07-29T20:10:01Z` | `957cce1f0c51b0bf6c42f2fd857aed962b03855084accd25240ab9339cf64ada` | 1 | 13.18 GiB | `removed` |
| `2026-07-30T02:12:14Z` | `72b35fbaa3352d1ef5f0e2e7f93c624f82c3428841c04330ed6e01254ac2ee50` | 2 | 35.15 GiB | `removed` |

### Pre-Baseline-Kontext: Cache-Receipt am Ausgangspunkt

Der folgende Receipt endete 8 Minuten und 49 Sekunden vor der Baseline. Er belegt den bereinigten Ausgangszustand, wird aber weder als Rückgewinnung im Beobachtungsfenster noch als Gegenposten zum späteren Cache-Zufluss gezählt.

| Abschluss (UTC) | Receipt-SHA-256 | Einträge | Freigegeben | Ergebnis |
|---|---|---:|---:|---|
| `2026-07-15T21:04:37Z` | `1207c22224f6cec12563009acf6437076c3ba11372ca0ece5c4c12497c543010` | 14 | 40.41 GiB | `removed` |

## Explizite Ausnahmen und Grenzen

- `repo-worktrees`: 20.19 GiB Nettorückgang; Endbestand 150.91 GiB bleibt über dem Hard-Limit 120.00 GiB. Der Mindest-Bruttozufluss von 340.94 GiB zeigt weiterhin hohen Erzeugungsdruck.
- `user-cache`: Endbestand 233.86 GiB liegt über dem Hard-Limit 50.00 GiB und wuchs im Fenster um 181.69 GiB. Ein einmaliger Baseline-Cleanup begrenzt fortgesetzten Zufluss nicht.
- `grabowski-releases`: Endbestand 20.29 GiB liegt knapp über dem Hard-Limit 20.00 GiB; Dauerbeweise dürfen nicht durch eine Budgetanhebung kaschiert werden.
- Unregistrierte Kandidaten bleiben sichtbar, aber unklassifiziert und nicht löschbar:
  - `/home/alex/repos/.commonworld-worktrees`: 3.77 GiB.
  - `/home/alex/repos/.grabowski-worktrees`: 2.86 GiB.

## Schwellenentscheidung

- Keine Schwelle wird geändert.
- Begründung: Die Überschreitungen sind nicht als harmlose Normalverteilung belegt. Die Worktree-Rückgewinnung überstieg zwar den Mindestzufluss und senkte den Bestand, dieser bleibt jedoch im Hard-Limit; der Mindestzufluss von 340.94 GiB bleibt hoch. Für den Cache ist im Fenster keine Rückgewinnung belegt, während sein Bestand um 181.69 GiB wuchs. Höhere Grenzwerte würden den Alarm nur verzögern.
- Folge: bestehende Warn- und Hard-Limits bleiben als Diagnosegrenzen bestehen. Diese Entscheidung erzeugt keine Cleanup-, Lösch- oder Break-glass-Autorität.

## Präventions- und Recovery-Readback

- Das post-gate erzeugte Endinventar klassifiziert `repo-worktrees`, `user-cache` und `grabowski-releases` als `hard_limit` und projiziert große unregistrierte Worktree-Wurzeln. Die Präventionsdiagnose ist damit aktiv und fail-closed.
- Die 15 Worktree-Receipts binden Kandidaten, Post-Move-Beobachtung und Post-Move-Tree-Hash; alle 45 ausgewerteten Outcomes lauten `removed`.
- Der Cache-Receipt bindet Vorher-/Nachher-Allokation unmittelbar vor der Baseline und alle ausgewerteten Outcomes lauten `removed`; er wird nicht dem Beobachtungsfenster zugerechnet.
- Nach dem Endinventar waren `leitstand-storage-health.timer` und `heim-pc-worktree-target-maintenance.timer` jeweils geladen, aktiviert und im Zustand `active/waiting`; die zugehörigen letzten Servicezustände meldeten `Result=success` und `ExecMainStatus=0`.

## Abschluss und Folgegrenze

- Das zeitliche Wirksamkeitsgate ist erfüllt; `STORAGE-LIFECYCLE-V1-T009` kann revisionsgebunden abgeschlossen werden.
- Nicht erfüllt ist dauerhafte Budgetkonformität. Der nächste Arbeitsgegenstand muss den Cache-Zufluss, den verbleibenden Worktree-Erzeugungsdruck und die knapp überschrittene Release-Retention getrennt behandeln, statt Schwellen anzuheben.

## Nichtaussagen

- Die Prüfung belegt keine Entbehrlichkeit weiterer Worktrees, keine Löschfreigabe, keine Backup-Suffizienz und keine Docker-Volume-Sicherheit.
- Zwei vollständige Inventare belegen Start und Ende; sie belegen keine tägliche Form der Wachstumskurve.
- Erfolgreiche Rückgewinnung beweist nicht, dass der Bestand dauerhaft innerhalb des Budgets bleibt.
