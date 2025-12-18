# Zonen & Bedeutungen

## Was sind Zonen?

Zonen sind **semantische Bereiche** deines Dateisystems mit definierter Bedeutung und Rolle.

## Warum Zonen?

Ohne Zonen ist `/home/alex/repos/tools` nur ein Pfad. Mit Zonen wird es:

* **Name**: `tools`
* **Typ**: `development`
* **Rolle**: `active-dev`
* **Bedeutung**: "Werkzeuge und Utilities in aktiver Entwicklung"

## Zonen-Konfiguration

Zonen werden in `config/zones.yml` definiert (manuell + KI-Vorschläge).

### Beispiel-Zone

```yaml
zones:
  - path: /home/alex/repos/tools
    name: tools
    type: development
    role: active-dev
    priority: high
    description: "Werkzeuge und Utilities in aktiver Entwicklung"
    
  - path: /home/alex/vault-gewebe
    name: vault-gewebe
    type: knowledge
    role: knowledge-base
    priority: high
    description: "Wissensmanagement und Notizen"
    
  - path: /home/alex/Downloads
    name: downloads
    type: transient
    role: staging
    priority: low
    description: "Temporäre Downloads und Staging-Bereich"
```

## Zonen-Typen

* **development** – Code, Repositories, aktive Projekte
* **knowledge** – Dokumentation, Notizen, Wikis
* **archive** – Historische Daten, alte Projekte
* **transient** – Temporäre Dateien, Downloads, Cache
* **config** – Konfigurationsdateien, Dotfiles
* **media** – Bilder, Videos, Audio
* **documents** – Dokumente, PDFs, Office-Dateien

## Zonen-Rollen

* **active-dev** – In aktiver Entwicklung
* **maintenance** – Wartungsmodus
* **archived** – Archiviert, nicht aktiv
* **knowledge-base** – Wissenssammlung
* **staging** – Temporärer Bereich
* **config-source** – Konfigurationsquelle

## Prioritäten

* **high** – Wichtig für tägliche Arbeit
* **medium** – Regelmäßig genutzt
* **low** – Selten oder temporär

## KI-Vorschläge

Webmaschine kann automatisch Zonen vorschlagen basierend auf:

* Pfad-Namen (repos, projects, docs, etc.)
* Datei-Typen (viele .py → development)
* Git-Repositories (aktive Commits → active-dev)
* Aktivität (letzte Änderungen)

Diese Vorschläge werden in `state/uncertainties.json` gespeichert und können manuell in `config/zones.yml` übernommen werden.

## Best Practices

1. **Start klein**: Beginne mit 3-5 Haupt-Zonen
2. **Manuell definieren**: KI-Vorschläge prüfen, dann manuell übernehmen
3. **Konsistent benennen**: Einheitliche Namen und Typen
4. **Dokumentieren**: Description ist wichtig für Kontext
5. **Regelmäßig reviewen**: Zonen können sich ändern

## Anti-Patterns

* ❌ Zu viele Zonen (>20) – zu granular
* ❌ Automatisch übernehmen ohne Review
* ❌ Zonen ohne Description
* ❌ Inkonsistente Typen/Rollen
* ❌ Keine Prioritäten setzen
