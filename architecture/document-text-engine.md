---
id: document-text-engine
role: norm
status: canonical
last_reviewed: 2026-08-24
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - tests/test_document_text_engine.py
  - tests/test_operator_entry.py
---

# Document Text Engine

## Zweck

`heim-pc` stellt eine kanonische, lokale Oberfläche für `document.text_extract` bereit. Sie ersetzt keine allgemeine Dokumentenverwaltung und keinen Cloud-Dienst. Sie macht nur die bereits vorhandenen lokalen OCR-/PDF-Werkzeuge über einen reproduzierbaren, maschinenlesbaren Einstieg auffindbar.

Maschinenlesbare Verträge:

- `manifest/document-text-engine-policy.v1.json` – lokale Werkzeuge, Routing, Sprachen und harte Grenzen;
- `manifest/document-text-contract.v1.json` – Ergebnisvertrag;
- `manifest/operator-entry.v1.json` – Capability-Locator für generische Operator-Intents;
- `scripts/document_text_engine.py` – kanonischer CLI-Einstieg.

## Operationen

```text
python3 scripts/document_text_engine.py doctor
python3 scripts/document_text_engine.py inspect /pfad/dokument.pdf
python3 scripts/document_text_engine.py extract /pfad/dokument.pdf
```

Alle Antworten sind JSON. Fehler werden als maschinenlesbarer `blocked`-Zustand ausgegeben; unbekannte Formate oder fehlende lokale Werkzeuge werden nicht geraten oder still durch einen anderen Provider ersetzt.

## Routing

Der Default ist deterministisch und local-first:

1. **PDF mit erkannter Textebene** → `pdftotext`.
2. **PDF ohne erkannte Textebene** → `OCRmyPDF` in ein temporäres Verzeichnis, danach `pdftotext`.
3. **Bild** → Tesseract.
4. **Komplexes Layout / Docling** → v1 nur nach expliziter lokaler Offline-Readiness-Evidenz; niemals automatische Modell-Downloads oder stilles Netzwerk.

Bei PDFs bedeutet „Textebene erkannt“ bewusst: **jede** durch die Seitenbegrenzung zugelassene Seite enthält nicht-leeren extrahierbaren Text. Sobald mindestens eine Seite keine Textebene trägt, läuft das gesamte Dokument über `OCRmyPDF --skip-text`; vorhandene Textseiten bleiben dabei unangetastet, während nur textlose Seiten OCR erhalten. So gehen bei gemischten Text-/Scan-PDFs keine Scan-Seiten still verloren.

Die Textebenenprüfung ist eine Routing-Heuristik und keine Aussage über semantische Vollständigkeit. Eine falsch negative Prüfung kann deshalb OCR auslösen; sie darf aber nicht zu Cloud-Eskalation führen.

## Sicherheits- und Kostenvertrag

- Standardpfad: null zusätzliche nutzungsabhängige Kosten.
- Keine Netzwerk- oder Cloud-Autorisierung durch den Locator oder die Engine.
- Quelldateien werden nicht verändert.
- Temporäre OCR-Produkte leben ausschließlich in einem temporären Arbeitsverzeichnis.
- Quellinhalt und extrahierter Text werden nicht als Betriebszustand persistiert.
- Ergebnisse sind an SHA-256 der exakten Quelldatei gebunden.
- Maximalgröße, Seitenzahl, Prozessdauer und modellvisible Ausgabe sind hart begrenzt.
- Symlink-Quellen werden in v1 abgewiesen, damit der geprüfte Pfad nicht unbemerkt auf eine andere Datei umschwenkt.

## Docling

Docling ist absichtlich **kein automatischer v1-Extractor**. Die lokale Installation allein beweist nicht, dass alle benötigten Modelle bereits lokal vorliegen. `doctor` unterscheidet daher zwischen installiert und explizit offline-readiness-attestiert. Ohne gültige Readiness-Evidenz darf ein Operator Docling nicht als automatischen Fallback interpretieren.

Diese Grenze verhindert, dass ein scheinbar lokaler OCR-Auftrag beim ersten Lauf unerwartet Modelle aus dem Netz lädt.

## Was die Engine nicht beweist

Ein erfolgreicher Lauf beweist nicht:

- semantische Richtigkeit oder Vollständigkeit des extrahierten Texts;
- Layouttreue;
- Dokumentauthentizität;
- gute Handschrifterkennung;
- Berechtigung für Cloud- oder Metered-Nutzung.

Für solche Aussagen ist zusätzliche, aufgabenspezifische Evidenz nötig.
