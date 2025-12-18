# Weltmodell-Konzept

## Was ist das "Weltmodell"?

Webmaschine erstellt ein **versioniertes Abbild** deines lokalen Rechners, das von KI-Systemen (wie Heimgewebe) gelesen und verstanden werden kann.

### Kernidee

Statt dass ein KI-Agent deinen ganzen Rechner "live" durchsuchen muss, bietet Webmaschine:

1. **Einen Index** (`state/index.json`) – Wo anfangen? Was ist wichtig?
2. **Semantische Zonen** (`config/zones.yml`) – Was bedeuten die Bereiche?
3. **Repository-Tracking** (`state/repos.json`) – Welche Repos sind aktiv?
4. **Drift-Erkennung** – Was hat sich verändert? Warum?
5. **Timeline** – Chronologische Historie der Änderungen

### Zwei-Schichten-Architektur

#### Schicht 1: Kanonische, kleine Artefakte (im Git-Repo)

* `state/index.json` – Einstiegspunkt für KI (< 10 KB)
* `state/repos.json` – Repository-Übersicht (< 50 KB)
* `state/summary.md` – Mensch-lesbarer Überblick
* `snapshots/latest.fs.summary.json` – Aggregationen (< 100 KB)

#### Schicht 2: Große Rohdaten (außerhalb Git)

* Vollständige Filesystem-Snapshots als GitHub Artifacts
* Release Assets für archivierte Snapshots
* Optionally: Git LFS für große Binärdaten
* Lokal in `~/vault-gewebe/...` für persönliche Archivierung

### Philosophie

> Das Dateisystem ist wie ein Dachboden. Wenn man "Ordnung" ruft, antwortet es mit 37 "final_v7_neu2.pdf".

Webmaschine akzeptiert diese Realität und schafft **Übersicht ohne Zwang zur Perfektion**.

## Nutzen für Heimgewebe

Heimgewebe kann durch Webmaschine:

1. **Sofort orientieren**: Index zeigt Hotspots und aktive Bereiche
2. **Semantisch navigieren**: Zonen geben Kontext und Bedeutung
3. **Drift verstehen**: Was hat sich warum verändert?
4. **Historie nutzen**: Timeline für zeitbasierte Analysen
5. **Effizient arbeiten**: Keine Live-Scans, sondern strukturierte Daten

## Abgrenzung

Webmaschine ist **nicht**:

* Ein Backup-System (nutze dafür restic, borg, etc.)
* Ein Sync-Tool (nutze dafür syncthing, rclone, etc.)
* Ein Datei-Manager (nutze dafür ranger, nnn, etc.)
* Eine Datenbank (es ist ein Abbild, kein aktives System)

Webmaschine ist ein **Orientierungssystem** für KI-Agenten.

## Beispiel-Daten

### Beispiel state/index.json

```json
{
  "machine": {
    "name": "pop-os-alex",
    "roots": ["/home/alex"],
    "hub": "/home/alex/repos"
  },
  "hotspots": [
    {"path": "/home/alex/repos/tools", "why": "active dev"},
    {"path": "/home/alex/vault-gewebe", "why": "knowledge"}
  ],
  "repos": {
    "count": 42,
    "active_last_7d": ["tools", "metarepo", "wgx"]
  },
  "artifacts": {
    "latest_snapshot": "snapshots/latest.fs.snapshot.ref",
    "timeline": "timeline/fs.timeline.jsonl"
  },
  "metadata": {
    "version": "0.1.0",
    "last_updated": "2024-12-18T10:30:00Z",
    "schema_version": "1.0"
  }
}
```

### Beispiel config/zones.yml

```yaml
zones:
  - path: /home/alex/repos
    name: repos
    type: development
    role: active-dev
    priority: high
    description: "Main repository directory"
  
  - path: /home/alex/vault-gewebe
    name: vault-gewebe
    type: knowledge
    role: knowledge-base
    priority: high
    description: "Knowledge management"
  
  - path: /home/alex/Downloads
    name: downloads
    type: transient
    role: staging
    priority: low
    description: "Temporary downloads"
```

### Beispiel Hotspot-Typen

* **active dev**: Aktive Entwicklung, häufige Commits
* **knowledge**: Dokumentation, Notizen, Wikis
* **staging**: Temporäre Dateien, Work-in-Progress
* **archive**: Selten genutzt, historisch wichtig
* **config**: Konfigurationsdateien, Dotfiles

