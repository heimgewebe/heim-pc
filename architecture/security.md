---
id: security
role: norm
status: canonical
last_reviewed: 2026-09-02
depends_on: []
verifies_with: []
---

# Sicherheit & Datenpolitik

## Grundprinzipien

1. **Privacy by Design** – Sensible Daten nie ins Repository
2. **Minimal Exposure** – Nur notwendige Pfade scannen
3. **Token Security** – Tokens nur für non-loopback
4. **Error Safety** – Keine sensitiven Details in Exceptions
5. **Metadata Only** – Weltmodell ist Struktur, nicht Inhalte

## Datenpolitik: Was wird erfasst?

### ✅ Was Heim-PC ERFASST

* **Metadaten**: Dateipfade, Größen, Timestamps, Typen
* **Struktur**: Verzeichnisbäume, Repository-Listen, Zonen
* **Aggregationen**: Statistiken, Summaries, Hotspots
* **Referenzen**: Pointer zu Snapshots (nicht die Snapshots selbst)

### ❌ Was Heim-PC NICHT ERFASST

* **Dateiinhalte**: Keine Dokumente, Code, Notizen gelesen
* **Credentials**: Keine Passwörter, Keys, Tokens gespeichert
* **Sensible Pfade**: `.ssh`, `.gnupg`, Browser-Profile ausgeschlossen
* **Personenbezogene Daten**: Keine E-Mails, Chat-Historie, etc.

### Drei Schutz- und Zustandsflächen

1. **Öffentliches Git-Repository (klein, reviewbar)**:
   - normative Architektur, Policies und kleine Maschinenverträge;
   - Konfiguration ohne Secret-Material;
   - `state/` nur soweit `architecture/model.md` das konkrete Artefakt ausdrücklich als quellengebundene Projektion oder historische Fixture zulässt. `state/index.json` und `state/repos.json` sind insbesondere keine aktuelle Hostwahrheit.

2. **Lokaler quellengebundener Betriebszustand außerhalb Git**:
   - Receipts, Driftberichte und volatile Inventare unter `~/.local/state/heim-pc/`;
   - jedes aktuelle Artefakt mit Quelle, Zeitpunkt, Hashbindung und Frischegrenze gemäß `architecture/model.md`.

3. **Große Daten, Backups und externe Artefakte**:
   - Nutzdaten und Backups außerhalb der Git-Historie;
   - CI-/Release-Artefakte nur für dafür geeignete, nicht-sensitive Daten;
   - Off-host-Backups folgen einem eigenen Recovery-Vertrag und sind keine Runtime-Wahrheit.

**Goldene Regel**: Klein committen, groß auslagern. Git ist Soll-/Normquelle, nicht Livezustand.

## Root-Grenzen

Heim-PC darf **nur** innerhalb definierter Root-Pfade browsen.

### Konfiguration (config/heim-pc.yml)

```yaml
roots:
  - /home/username  # Nur User-Home
  # NICHT: /home, /, /root, /etc
```

### Warum?

* Verhindert versehentliches Scannen von System-Bereichen
* Vermeidet Permission-Probleme
* Schützt andere Nutzer-Accounts
* Minimiert Angriffsfläche

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

Zusätzliche Excludes in `config/heim-pc.yml`:

```yaml
excludes:
  - pattern: "*/secret/*"
    reason: "Sensitive data directory"
  - pattern: "*.key"
    reason: "Private keys"
  - pattern: "/home/alex/personal-backup/*"
    reason: "Large backup directory"
```

## Lokale Endpunkt- und Token-Sicherheit

### Regel: Loopback ist lokal, aber nicht automatisch vertrauenswürdig

* **Non-loopback** (LAN, Tailnet, Internet): Authentisierung ist grundsätzlich erforderlich.
* **Loopback** (`localhost`, `127.0.0.1`, `::1`) und lokale Unix-Sockets sind nur eine Transportgrenze. Auf demselben Host kann nicht vertrauenswürdiger Projekt-, Build- oder Containercode laufen; die lokale Adresse allein erteilt daher keine Autorität.
* Operator-, Secret-, Mutations- oder privilegierte Endpunkte benötigen auch lokal eine geeignete Capability, Authentisierung/Peer-Bindung oder eine nachweisbare Netzwerk-/Prozessisolation.
* Ein unauthentisierter Loopback-Health-Endpunkt ist nur zulässig, wenn er read-only, datensparsam und ausdrücklich als niedriges Risiko klassifiziert ist und keine privilegierte Folgeaktion auslösen kann.

### Explizite öffentliche Diagnosekonstante

Die festen **loopback-only** Health-Listener-Zuordnungen in `scripts/tunnel_profile_diagnostics.py` und die dazugehörige README-Dokumentation sind eine bewusst minimierte öffentliche Ausnahme von der allgemeinen Regel gegen konkrete interne Listener-Mappings. Sie enthalten weder Non-loopback-Adressen noch Tokens und dienen ausschließlich deterministischer Kollisions-/Profilprüfung.

Diese Veröffentlichung ist **keine Sicherheitsgrenze und keine Authentisierungsfreigabe**. Sobald ein solcher Listener Non-loopback erreichbar, operatorfähig, secrettragend oder mutierend wird, erlischt die Ausnahme; dann sind Zieladresse und Authentisierungsvertrag separat zu reviewen.

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

Das Repository `heimgewebe/heim-pc` ist öffentlich. Die Bezeichnung „lokaler/privater Maschinen-Einstieg“ in der Architektur beschreibt den Gegenstand und die lokale Operatorrolle, **nicht** eine Vertraulichkeitsgrenze des Git-Repositorys. Repository-Sichtbarkeit darf niemals als Schutz für sensitive Hostdetails vorausgesetzt werden.

* kleine normative Verträge und Konfiguration ohne Secrets;
* abstrahierte Pfad-Strukturen ohne sensible Namen;
* aggregierte Größen/Timestamps nur, wenn sie keine private Nutzung offenlegen;
* öffentliche Repository-Referenzen.

Nicht versionieren: Geräte-Seriennummern, MAC-Adressen, private LAN-Topologie, konkrete interne Listener/Ports, private Hostnamen oder andere hochauflösende Recon-Daten, sofern sie nicht für einen ausdrücklich geprüften öffentlichen Vertrag unvermeidbar und minimiert sind.

#### NICHT im Git-Repository

* Datei-Inhalte
* Sensible Pfad-Namen (`.ssh`, `.gnupg`, etc.)
* Private Repository-Details
* Persönliche Notizen/Dokumente
* Credentials, Tokens, Keys

### Snapshot-Artefakte

Das öffentliche Repository ist **keine Vertraulichkeitsgrenze für CI-/Release-Artefakte**. Vollständige oder sensitive Hostsnapshots dürfen deshalb nicht allein aufgrund eines GitHub-Artifact-/Release-Mechanismus als „privat“ gelten.

* Sensitive Vollsnapshots werden nicht in GitHub Actions oder Releases publiziert, solange kein separat belegter Zugriffsschutz und eine dafür freigegebene Datenklassifikation existiert.
* Zulässige CI-Artefakte enthalten nur bereits freigegebene, minimierte oder nicht-sensitive Daten.
* Retention begrenzt Lebensdauer, ersetzt aber keine Zugriffskontrolle.
* Private Backups und Recovery-Artefakte gehören in den separaten Off-host-Backup-Vertrag, nicht in die öffentliche Repo-/CI-Fläche.

## Compliance

### GDPR

* Keine personenbezogenen Daten im Repository
* Keine sensitiven Snapshots in öffentlichen Repo-/CI-Flächen ohne separat belegte Zugriffskontrolle
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
- [ ] CI-/Release-Artefakte gegen öffentliche Repo-Sichtbarkeit und Datenklassifikation geprüft
