# Speicher-Wirksamkeitsprüfung: Zwischenstand vom 29. Juli 2026

## Urteil

> **Fortsetzungsgate:** Das Mindestfenster von 14 vollständigen Tagen endet erst `2026-07-29T21:13:26.256171Z`. Das gebundene Endinventar entstand um `2026-07-29T19:28:05.793425Z` und liegt damit 1 Stunde, 45 Minuten und 20 Sekunden vor dem Gate. Dieser Zwischenstand darf `STORAGE-LIFECYCLE-V1-T009` daher noch nicht terminalisieren und der PR darf auf diesem Stand nicht gemergt werden.

- **Schwellen bleiben unverändert.** Die Messwerte rechtfertigen keine Lockerung; mehrere Produzenten liegen trotz funktionierender Rückgewinnung über ihren Hard-Limits.
- **Die Bereinigungsmechanik wirkt, begrenzt aber den Zufluss nicht ausreichend.** Im Beobachtungsfenster wurden Worktree-Targets revisionsgebunden entfernt, während der gemessene Worktree-Bestand netto weiter wuchs.
- **Die globale Ausnahme bleibt ausdrücklich aktiv.** Temporäre plus regenerierbare Daten überschreiten das globale Hard-Budget. Das ist ein Befund, keine Löschfreigabe.
- **Prävention und Recovery sind belegt, aber nicht gleichbedeutend mit Budgeteinhaltung.** Inventar und Timer erkennen Überschreitungen; Worktree-Receipts belegen Rückgewinnung im Fenster, der Cache-Receipt nur den Zustand unmittelbar vor der Baseline.

## Evidenzbindung

- Beobachtungsfenster: `2026-07-15T21:13:26.256171Z` bis `2026-07-29T19:28:05.793425Z` (13 Tage, 22 Stunden; Kalendertage 15.–29. Juli 2026).
- Baseline: `/home/alex/.local/state/heim-pc/storage-remediation/STORAGE-LIFECYCLE-V1-T008/storage-inventory-final.json`, Datei-SHA-256 `10dbc82106e450500b158c8261eded5cbd0f8f9a15ec215e32b06cc31b17afdd`, Inventar-SHA-256 `c3b2a14b0a7108dc3434476e75843cb76c47bb4127923f0988c79c899ef00324`.
- Endinventar: lokal frisch aus Commit `739970a4326c1aae6f6cb451f0a93206dcc30830` erzeugt, Datei-SHA-256 `36139a9ca7376f35e8838ab7fc2c130a1f174f97b90a66af86ce9f3a9503132e`, Inventar-SHA-256 `479bf1d9dba1ed75918c960eef040e35afd9194d32ee55fe807edefdbc0b88e7`.
- Richtlinie: `config/storage-lifecycle.v1.json`, Datei-SHA-256 `5f9ee22e12a771059bac9b9550f54b99fa1f9b3ca9ce9d982f9645890c7816c7`.
- Zwischenzeitliche Bestandsverläufe werden nicht erfunden: Es liegen zwei vollständige Inventare und dazwischen hashgebundene Cleanup-Receipts vor. Der genaue Tagesverlauf innerhalb des Fensters bleibt unbekannt.

## Produzenten

| Produzent | Klasse | Start | Ende | Delta | Startstatus | Endstatus | Hard-Limit |
|---|---:|---:|---:|---:|---|---|---:|
| `repo-worktrees` | `temporary_workspace` | 171.11 GiB | 196.90 GiB | +25.80 GiB | `hard_limit` | `hard_limit` | 120.00 GiB |
| `repobrief-auto` | `temporary_workspace` | 1.13 GiB | 1.13 GiB | +0.00 GiB | `ok` | `ok` | 40.00 GiB |
| `user-cache` | `regenerable_cache` | 52.17 GiB | 232.30 GiB | +180.13 GiB | `hard_limit` | `hard_limit` | 50.00 GiB |
| `trash` | `temporary_workspace` | 21.22 GiB | 0.11 GiB | -21.11 GiB | `hard_limit` | `ok` | 20.00 GiB |
| `grabowski-releases` | `durable_evidence` | 10.12 GiB | 20.29 GiB | +10.17 GiB | `warning` | `hard_limit` | 20.00 GiB |
| `vm-data` | `canonical` | 15.17 GiB | 15.17 GiB | +0.00 GiB | `ok` | `ok` | 100.00 GiB |

## Klassen und globales Budget

| Klasse | Start | Ende | Delta |
|---|---:|---:|---:|
| `canonical` | 15.17 GiB | 15.17 GiB | +0.00 GiB |
| `durable_evidence` | 10.12 GiB | 20.29 GiB | +10.17 GiB |
| `regenerable_cache` | 52.17 GiB | 232.30 GiB | +180.13 GiB |
| `temporary_workspace` | 193.46 GiB | 198.14 GiB | +4.68 GiB |

- Temporär plus regenerierbar: 245.63 GiB → 430.44 GiB.
- Globales Warnbudget: 100.00 GiB; globales Hard-Budget: 150.00 GiB.
- Explizite Ausnahme am Ende: 280.44 GiB über dem Hard-Budget. Sie autorisiert keine Löschung.
- Dateisystembelegung: 31.46% → 57.64%; der globale Dateisystemstatus bleibt `ok`.

## Rückgewinnung im Fenster

- Worktree-Target-Maintenance: 13 Receipts, 42 entfernte Targets, 312.80 GiB belegte Blöcke entfernt.
- Daraus folgt für `repo-worktrees` ein Bruttozufluss von mindestens 338.60 GiB: entfernte Bytes plus positives Nettowachstum.
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

### Pre-Baseline-Kontext: Cache-Receipt am Ausgangspunkt

Der folgende Receipt endete 8 Minuten und 49 Sekunden vor der Baseline. Er belegt den bereinigten Ausgangszustand, wird aber weder als Rückgewinnung im Beobachtungsfenster noch als Gegenposten zum späteren Cache-Zufluss gezählt.

| Abschluss (UTC) | Receipt-SHA-256 | Einträge | Freigegeben | Ergebnis |
|---|---|---:|---:|---|
| `2026-07-15T21:04:37Z` | `1207c22224f6cec12563009acf6437076c3ba11372ca0ece5c4c12497c543010` | 14 | 40.41 GiB | `removed` |

## Explizite Ausnahmen und Grenzen

- `repo-worktrees`: 25.80 GiB Nettowachstum; Endbestand 196.90 GiB über Hard-Limit 120.00 GiB.
- `user-cache`: Endbestand 232.30 GiB über Hard-Limit 50.00 GiB. Ein einmaliger Baseline-Cleanup begrenzt fortgesetzten Zufluss nicht.
- `grabowski-releases`: Endbestand 20.29 GiB liegt knapp über Hard-Limit 20.00 GiB; Dauerbeweise dürfen nicht durch eine Budgetanhebung kaschiert werden.
- Unregistrierte Kandidaten bleiben sichtbar, aber unklassifiziert und nicht löschbar:
  - `/home/alex/repos/.commonworld-worktrees`: 3.77 GiB.
  - `/home/alex/repos/.grabowski-worktrees`: 2.78 GiB.

## Schwellenentscheidung

- Keine Schwelle wird geändert.
- Begründung: Die Überschreitungen sind nicht als harmlose Normalverteilung belegt. Der Worktree-Zufluss übersteigt die im Fenster nachgewiesene Rückgewinnung; für den Cache ist im Fenster keine Rückgewinnung belegt. Höhere Grenzwerte würden nur den Alarm verzögern.
- Folge: bestehende Warn- und Hard-Limits bleiben als Diagnosegrenzen bestehen. Diese Entscheidung erzeugt keine Cleanup-, Lösch-, Merge- oder Break-glass-Autorität.

## Präventions- und Recovery-Readback

- Das frisch erzeugte Endinventar klassifiziert `repo-worktrees`, `user-cache` und `grabowski-releases` als `hard_limit` und projiziert große unregistrierte Worktree-Wurzeln. Die Präventionsdiagnose ist damit aktiv und fail-closed.
- Die Worktree-Receipts binden Kandidaten, Post-Move-Beobachtung und Post-Move-Tree-Hash; alle im Fenster ausgewerteten Outcomes lauten `removed`.
- Der Cache-Receipt bindet Vorher-/Nachher-Allokation unmittelbar vor der Baseline und alle ausgewerteten Outcomes lauten `removed`; er wird nicht dem Beobachtungsfenster zugerechnet.
- Timer-Readback zum Prüfzeitpunkt:
```text
NextElapseUSecRealtime=Wed 2026-07-29 22:03:46 CEST
LastTriggerUSec=Wed 2026-07-29 21:04:28 CEST
Id=leitstand-storage-health.timer
ActiveState=active
SubState=waiting

NextElapseUSecRealtime=
LastTriggerUSec=Wed 2026-07-29 16:09:24 CEST
Id=heim-pc-worktree-target-maintenance.timer
ActiveState=active
SubState=waiting
```

## Nichtaussagen

- Die Prüfung belegt keine Entbehrlichkeit weiterer Worktrees, keine Löschfreigabe, keine Backup-Suffizienz und keine Docker-Volume-Sicherheit.
- Zwei vollständige Inventare belegen Start und Ende; sie belegen keine tägliche Form der Wachstumskurve.
- Erfolgreiche Rückgewinnung beweist nicht, dass der Bestand dauerhaft innerhalb des Budgets bleibt.
