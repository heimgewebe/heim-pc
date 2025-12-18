# Sicherheit & Datenpolitik

## Grundprinzipien

1. **Privacy by Design** – Sensible Daten nie ins Repository
2. **Minimal Exposure** – Nur notwendige Pfade scannen
3. **Token Security** – Tokens nur für non-loopback
4. **Error Safety** – Keine sensitiven Details in Exceptions

## Root-Grenzen

Webmaschine darf **nur** innerhalb definierter Root-Pfade browsen.

### Konfiguration (config/webmaschine.yml)

```yaml
roots:
  - /home/alex
  # NICHT: /home, /, /root, /etc
```

### Warum?

* Verhindert versehentliches Scannen von System-Bereichen
* Vermeidet Permission-Probleme
* Schützt andere Nutzer-Accounts

## Excludes

Folgende Pfade werden **immer** ausgeschlossen:

### System & Cache

* `.cache/`
* `.local/share/Trash/`
* `node_modules/`
* `.venv/`, `venv/`
* `dist/`, `build/`, `target/`
* `__pycache__/`
* `.mypy_cache/`, `.pytest_cache/`

### Browser & Sensible Daten

* `.mozilla/firefox/*/` (Profile)
* `.config/google-chrome/*/` (Profile)
* `.thunderbird/*/` (Profile)
* `.ssh/` (Keys)
* `.gnupg/` (Keys)
* `.password-store/` (Passwords)
* `*.key`, `*.pem`, `*.p12`

### Große/Temporäre Dateien

* `*.iso`, `*.img`, `*.dmg`
* `*.tar.gz`, `*.zip` (>100MB)
* `*.mp4`, `*.mkv`, `*.avi` (Videos)
* `*.war`, `*.jar` (große Java-Artefakte)

### Custom Excludes

Zusätzliche Excludes in `config/webmaschine.yml`:

```yaml
excludes:
  - pattern: "*/secret/*"
    reason: "Sensitive data directory"
  - pattern: "*.key"
    reason: "Private keys"
  - pattern: "/home/alex/personal-backup/*"
    reason: "Large backup directory"
```

## Token-Sicherheit

### Regel: Tokens nur für non-loopback

* **Loopback** (localhost, 127.0.0.1): Kein Token nötig
* **Non-loopback** (Netzwerk, Internet): Token erforderlich

### Warum?

* Loopback ist per Definition sicher (nur lokaler Zugriff)
* Netzwerk-Zugriff benötigt Authentifizierung
* Verhindert unautorisierten Remote-Zugriff

### Token-Storage

* **NIEMALS** im Git-Repository
* In `.env` (git-ignored)
* Oder in System-Keyring (z.B. `secret-tool`)

## Exception-Handling

### Intern (Logs)

```python
# OK: Detaillierte Logs lokal
logger.error(f"Failed to read {path}: {error}")
```

### Extern (UI/API)

```python
# OK: Generische Meldung
return {"error": "Failed to read file", "code": "READ_ERROR"}

# NICHT OK: Details leaken
return {"error": f"Failed to read /home/alex/.ssh/id_rsa: Permission denied"}
```

### Warum?

* Verhindert Information Disclosure
* Pfade können sensitive Info enthalten
* Error-Details können Attack-Vektoren zeigen

## Datenpolitik

### Was wird gespeichert?

#### Im Git-Repository (öffentlich)

* Pfad-Strukturen (ohne sensible Namen)
* Dateigrößen, Timestamps
* Repository-Namen (öffentliche Repos)
* Aggregierte Statistiken

#### NICHT im Git-Repository

* Datei-Inhalte
* Sensible Pfad-Namen (`.ssh`, `.gnupg`, etc.)
* Private Repository-Details
* Persönliche Notizen/Dokumente
* Credentials, Tokens, Keys

### Snapshot-Artefakte

Vollständige Snapshots (als GitHub Artifacts):

* **Privat**: Nur für Repo-Collaborators
* **Ephemeral**: Auto-Delete nach 90 Tagen
* **Optional**: Können deaktiviert werden

## Compliance

### GDPR

* Keine personenbezogenen Daten im Repository
* Snapshots privat und ephemeral
* Opt-in für Telemetrie (keine Standard-Aktivierung)

### Best Practices

* Regelmäßig `config/excludes` reviewen
* Vor Commit: `git diff` prüfen auf sensitive Daten
* Bei Versehen: `git filter-repo` zum Entfernen
* Security-Audit bei Major-Changes

## Incident Response

### Bei versehentlichem Commit von Secrets

1. **Sofort**: Secret rotieren (neues generieren)
2. **Git History**: `git filter-repo` zum Entfernen
3. **Force Push**: ⚠️ Koordination mit Team
4. **Review**: Wie konnte es passieren? Excludes anpassen

### Bei unauthorisiertem Zugriff

1. **Sofort**: Tokens widerrufen
2. **Audit**: Welche Daten wurden zugegriffen?
3. **Review**: Access-Logs prüfen
4. **Remediation**: Schwachstelle fixen

## Security Checklist

- [ ] Roots auf User-Home limitiert
- [ ] Alle sensiblen Pfade in Excludes
- [ ] Keine Tokens im Repository
- [ ] Exception-Handling ohne Details
- [ ] `.gitignore` für lokale Configs
- [ ] Regelmäßige Security-Reviews
- [ ] Snapshot-Artefakte auf "Private"
