# Drift-Definition

## Was ist Drift?

**Drift** beschreibt Veränderungen im Dateisystem, die nicht erwartet oder nicht dokumentiert sind.

## Drift-Kategorien

### 1. Erwarteter Drift (Normal)

* Neue Commits in aktiven Repositories
* Downloads in `/Downloads`
* Cache-Aufbau in `.cache`
* Log-Rotation in `/var/log`

### 2. Unerwarteter Drift (Attention)

* Neue große Dateien in unerwarteten Orten
* Repositories ohne Commits seit >90 Tagen in `active-dev` Zone
* Gigabytes an Daten in "transient" Zonen
* Neue Repositories ohne Zone-Zuordnung

### 3. Problematischer Drift (Action Required)

* Kritische Disk-Usage (>90%)
* Sensible Dateien außerhalb sicherer Zonen
* Duplikate von großen Dateien
* Broken symlinks
* Verwaiste `.git` Directories

## Drift-Erkennung

Drift wird erkannt durch:

1. **Snapshots vergleichen**: Aktuell vs. letzter Snapshot
2. **Zonen-Regeln**: Erwartetes Verhalten pro Zone
3. **Schwellwerte**: Größe, Anzahl, Zeitraum
4. **Anomalie-Erkennung**: Ungewöhnliche Muster

## Drift-Schwellwerte

```yaml
drift_thresholds:
  file_size_warning: 100MB      # Warnung bei neuen Dateien >100MB
  file_size_alert: 1GB          # Alert bei neuen Dateien >1GB
  repo_inactive_days: 90        # Repo als "inactive" nach 90 Tagen
  transient_size_warning: 10GB  # Warnung bei transient zone >10GB
  transient_size_alert: 50GB    # Alert bei transient zone >50GB
```

## Drift-Regeln pro Zone

### Development Zone

* ✅ Neue Dateien erwartet: `.py`, `.js`, `.go`, `.rs`
* ✅ Neue Repositories erwartet
* ⚠️ Große Binärdateien unerwartet (>50MB)
* ⚠️ Keine Aktivität >90 Tage

### Knowledge Zone

* ✅ Neue Markdown-Dateien erwartet
* ✅ Neue Notizen erwartet
* ⚠️ Große Media-Dateien (>10MB) sollten woanders
* ⚠️ Keine Aktivität >180 Tage

### Transient Zone

* ✅ Neue Dateien jederzeit erwartet
* ✅ Löschen von Dateien erwartet
* ⚠️ Total size >10GB
* 🚨 Total size >50GB

### Archive Zone

* ⚠️ Neue Dateien unerwartet (sollte statisch sein)
* ✅ Keine Änderungen erwartet
* 🚨 Löschen von Dateien (Datenverlust?)

## Drift-Reporting

Drift wird dokumentiert in:

* `state/uncertainties.json` – Ungeklärte Änderungen
* `timeline/fs.timeline.jsonl` – Chronologische Historie
* `state/summary.md` – Übersicht mit Highlights

### Beispiel Uncertainty Entry

```json
{
  "path": "/home/alex/repos/old-project",
  "issue": "repo_inactive",
  "details": {
    "last_commit": "2023-01-15",
    "days_inactive": 337,
    "zone": "active-dev"
  },
  "suggested_action": "move_to_archive_or_update_zone",
  "detected_at": "2024-12-18T15:00:00Z"
}
```

## Best Practices

1. **Regelmäßig reviewen**: Wöchentlich `state/uncertainties.json` prüfen
2. **Schwellwerte anpassen**: An deine Arbeitsweise anpassen
3. **Zonen aktualisieren**: Wenn Drift erwartet wird, Zone ändern
4. **Aufräumen**: Transient zones regelmäßig leeren
5. **Dokumentieren**: Große Änderungen in Timeline-Comments

## Anti-Patterns

* ❌ Drift ignorieren ohne Begründung
* ❌ Schwellwerte zu streng (zu viele False Positives)
* ❌ Keine Zone-Anpassung bei Verhalten-Änderung
* ❌ Sensible Daten in transient zones
* ❌ Aufräum-Aktionen ohne Backup
