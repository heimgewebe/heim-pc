---
id: cache-maintenance
role: norm
status: canonical
last_reviewed: 2026-07-15
depends_on:
  - storage-lifecycle
  - managed-builds
  - security
verifies_with:
  - config/cache-policy.v1.json
  - scripts/cache_maintenance.py
  - tests/test_cache_maintenance.py
---

# Begrenzte Cache- und Aufbewahrungspflege

## Zweck

`cache_maintenance.py` stellt einen einzigen, prüfbaren Ablauf für regenerierbare Daten und eng begrenzte Aufbewahrungsbestände bereit. Das Werkzeug trennt zwingend zwischen Beobachtung, Plan und Wirkung. Ein Plan allein erteilt keine Löschbefugnis.

Die kanonische Policy liegt unter `config/cache-policy.v1.json`.

## Klassen

| Klasse | Kandidaten | Wirkung |
|---|---|---|
| `filesystem_cache` | vollständig alte, eigentümerkontrollierte Kinder bekannter Cachewurzeln | exakte Datei- oder Verzeichnisentfernung |
| `trash` | zusammengehörige Payload- und `.trashinfo`-Paare mit ausreichendem Alter | paarweise Entfernung |
| `grabowski_releases` | alte Releases außer aktivem Release und den neuesten Fallbacks | exakte Releaseverzeichnisentfernung |
| `maintenance_journal` | alte eigene Plan- und Receiptdateien jenseits der Mindestanzahl | exakte Dateientfernung |
| `docker_build_cache` | der exakt beobachtete Satz alter, reclaimable und nicht mutabler BuildKit-Datensätze | filtergebundenes Prune nur bei identischem Readback |
| `docker_images` | ausschließlich alte dangling Images ohne Referenz durch irgendeinen Container | Entfernung per vollständiger Image-SHA |
| `user_journal` | nur Datenträgerbeobachtung | report-only, keine Vacuum-Wirkung |

Docker-Volumes werden weder inventarisiert noch an einen Löschbefehl übergeben.

## Sicherheitsmodell

### Plan

Ein Plan enthält:

- die SHA-256 der Policy;
- eine stabile Kandidaten-ID je Ziel;
- vor der Wirkung beobachtete Größen;
- Zustandsdigests für Dateisystemziele;
- exakte BuildKit-Record-IDs beziehungsweise Docker-Image-SHAs;
- eine klassenbezogene Bindung jedes Kandidaten an die registrierte Policywurzel oder Docker-Policy;
- alle Ausschlüsse mit Grund;
- die explizite Aussage `automatic_cleanup_authorized=false`.

Der Planhash bindet den Erzeugungszeitpunkt, die Policy und sämtliche Beobachtungen. Damit ist jede Planinstanz unveränderlich adressiert und kann keine frühere Instanz mit gleichem Kandidatensatz überschreiben. Bei festem Zeitpunkt und identischen Beobachtungen ist der Hash deterministisch. Der Speicherpfad selbst ist nicht Teil des Hashs.

### Apply

Alle Apply-Vorgänge desselben State-Roots werden über eine eigentümerkontrollierte, nicht symlinkfähige `flock`-Datei exklusiv serialisiert. Dadurch können parallele Operatorläufe weder dasselbe Receipt noch dieselbe Quarantäne gleichzeitig verändern.

Apply benötigt gleichzeitig:

1. eine gespeicherte Plan-Datei;
2. die erwartete Plan-SHA-256;
3. `APPLY:<plan_id>` als Bestätigung;
4. eine explizite, eindeutige Liste von Kandidaten-IDs.

Vor jeder Wirkung wird der Zielzustand erneut geprüft. Zusätzlich werden Plan-Home, Kandidatenform, Kandidaten-ID und die Zugehörigkeit zu einer registrierten Policywurzel neu validiert. Ein selbst korrekt gehashter, aber frei konstruierter Plan kann daher keine unbekannten Pfade oder abweichenden Docker-Parameter autorisieren. Drift blockiert fail-closed.

Dateisystemziele werden zunächst atomar in ein transaktionsgebundenes Quarantäneverzeichnis auf demselben Dateisystem verschoben. Bei einem normalen Fehler während der Verschiebung werden die in diesem Versuch bewegten Pfade zurückgestellt. Nach einem Prozessabbruch erkennt der nächste identische Apply jede bereits verschobene Teilmenge über eine verschiebungsstabile Identität aus Gerät, Inode, Modus, Größe und `mtime`; Pfad und durch `rename` veränderte `ctime` sind dafür bewusst nicht Teil der Recovery-Identität. Unbekannte Quarantäneeinträge oder Identitätsdrift blockieren. Das Receipt wird vor jedem Kandidaten aktualisiert; ein erneuter identischer Apply wiederholt vollständig abgeschlossene Kandidaten nicht.

### Prozess- und Eigentumsgrenzen

Dateisystemkandidaten werden ausgeschlossen, wenn:

- die Kandidatenwurzel selbst ein Symlink ist;
- ein Eintrag nicht dem ausführenden Benutzer gehört;
- ein Mountwechsel erkannt wird;
- ein eigener Prozess den Pfad als CWD, Executable oder offenen Dateideskriptor referenziert;
- die begrenzte Prozessbeobachtung unvollständig ist;
- der Kandidat die maximale Eintragszahl oder sein Scan-Zeitbudget überschreitet;
- das Gesamtzeitbudget des Plans erschöpft ist;
- ein aktiver Pin vorliegt.

Interne Symlinks werden als eigene Inode-Metadaten erfasst, aber nie verfolgt. Dadurch kann beispielsweise eine Python-Umgebung mit `lib64 -> lib` als vollständiger Cachebaum verschoben werden, ohne dass das Symlinkziel außerhalb des Kandidaten gelesen oder gelöscht wird.

BuildKit-Prune wird zusätzlich blockiert, wenn die Prozesssicht unvollständig ist oder ein `docker build`, `docker buildx build` beziehungsweise `buildctl build` beobachtet wird. Mutable BuildKit-Datensätze sind nie Kandidaten.

### Docker-Grenzen

Für Images gilt:

- nur `dangling=true` und Tag `<none>`;
- der Anzeigename in der Repository-Spalte allein ist nicht maßgeblich; `RepoTags` und `RepoDigests` aus `docker image inspect` müssen leer sein;
- vollständige SHA-256-Image-ID;
- keine Referenz durch laufende oder gestoppte Container;
- erneuter Dangling-, Referenz- und Altersreadback unmittelbar vor `docker image rm`;
- kein `--force`.

BuildKit bietet keine Löschung einzelner Cache-IDs. Deshalb darf der filtergebundene Prune nur laufen, wenn der unmittelbar davor erneut gelesene Record-Satz exakt dem geplanten Satz entspricht. Jede Teilmenge und jeder unerwartete neue Datensatz blockiert; ein unklar unterbrochener Prune wird nicht als erledigt hochgerechnet.

Docker-Volumes sind kategorisch außerhalb des Vertrags. Journald-Vacuum bleibt report-only, weil `journalctl --vacuum-*` keine exakte entfernende Zielmenge offenlegt.

## Pins

`pin` schützt eine Kandidaten-ID, einen Release-Namen, einen vollständigen Pfad oder eine Docker-ID zeitlich begrenzt. Jeder Pin benötigt Grund und TTL. Pins werden beim Plan, zu Beginn des Apply und unmittelbar vor jedem einzelnen Kandidaten erneut geprüft. Pin-Änderungen verwenden denselben exklusiven State-Lock wie Apply und können daher nicht zwischen finalem Readback und Wirkung rutschen. Sie erteilen keine positive Löschbefugnis.

## Receipts

Ein Apply-Receipt bindet:

- Plan- und Policy-SHA;
- exakte ausgewählte Kandidaten-IDs;
- Vorhergröße je Kandidat und insgesamt;
- Ergebnis und entfernte, klassenbezogen gemeldete Zielbytes je Kandidat;
- Nachhergröße der adressierten Zielmenge;
- die explizite Aussage, dass kein globaler Dateisystem-Freiplatzdelta gemessen wurde;
- Fehler und aktuellen Kandidaten bei Unterbrechung;
- `docker_volumes_touched=false`;
- eine eigene Receipt-SHA-256.

Ein vollständig abgeschlossenes Receipt wird bei identischem Request unverändert wiedergegeben. Dateisystempfade berichten belegte Blöcke, BuildKit berichtet die Differenz seiner reclaimable Bytes, Docker-Images ihre virtuelle Imagegröße. Diese Werte werden nicht als physisch freigegebener globaler Plattenplatz ausgegeben.

## Gegenbeispiele

Kein generischer Apply ist zulässig für:

- ein Docker-Image, das von einem gestoppten Container referenziert wird;
- ein getaggtes, lediglich lange unbenutztes Image;
- ein Docker-Volume;
- einen aktiven oder mutablen BuildKit-Datensatz;
- eine Grabowski-Runtime oder einen Fallback innerhalb des Schutzfensters; aktives Release und Fallbacksatz werden unmittelbar vor jeder Releaseentfernung erneut gelesen;
- einen Cachepfad mit offenem Dateideskriptor;
- Journald-Einträge ohne exakte adressierbare Zielmenge;
- unbekannte oder fremde Pfade unter `~/.cache`.

## Betriebsfolge

1. Policy validieren.
2. Dry-run-Plan erzeugen und Kandidaten sowie Ausschlüsse prüfen.
3. Bei Bedarf einzelne Kandidaten pinnen.
4. Nur ausdrücklich ausgewählte Kandidaten mit Planhash und Bestätigung anwenden.
5. Receipt und Nachhergrößen prüfen.
6. Historische Pläne und Receipts erst über denselben Lifecycle jenseits der Mindestaufbewahrung entfernen.
