# Zonen & Bedeutungen

## Was sind Zonen?

Zonen sind **semantische Bereiche** deines Dateisystems. Sie fassen einen oder mehrere Pfade unter einem gemeinsamen Zweck, einem Satz von Tags und einer empfohlenen Überprüfungsfrequenz zusammen. Sie sind das Kernkonzept, um einem KI-Agenten beizubringen, wie dein Dateisystem organisiert ist und welche Bereiche welche Art von Aufmerksamkeit erfordern.

## Warum das neue Zonen-Modell?

Das Zonen-Modell wurde weiterentwickelt, um KI-Agenten eine tiefere, flexiblere und nützlichere Analyse zu ermöglichen:

1.  **Mehrere Pfade pro Zone (`paths`):** Eine semantische Zone (z. B. "Alle Medien-Archive") kann sich über mehrere Verzeichnisse oder sogar Laufwerke erstrecken. Das neue Modell fasst diese unter einer einzigen logischen Zone zusammen.
2.  **Flexible Tags (`tags`):** Statt starrer `type`- und `role`-Felder ermöglicht ein flexibles Tag-System eine reichhaltigere Beschreibung. Tags wie `development`, `archive`, `high-priority` oder `temporary` können frei kombiniert werden.
3.  **Überprüfungsfrequenz (`review_frequency`):** Dieses neue Feld gibt der KI einen direkten Hinweis darauf, wie oft der Inhalt einer Zone überprüft werden sollte, um beispielsweise veraltete Dateien oder Archivierungskandidaten zu finden.

## Zonen-Konfiguration

Zonen werden manuell in `config/zones.yml` definiert. Die Struktur wird durch das kanonische Schema im `heimgewebe/metarepo` validiert, um die Konsistenz im gesamten Ökosystem zu gewährleisten.

### Beispiel-Zonen

```yaml
# config/zones.yml
zones:
  - name: "core-projects"
    paths:
      - "/home/alex/repos/work"
      - "/home/alex/dev/side-projects"
    purpose: "Enthält primäre Entwicklungsprojekte und aktive Repositories."
    tags:
      - "development"
      - "high-priority"
      - "active"
    review_frequency: "monthly"

  - name: "media-archives"
    paths:
      - "/mnt/nas/photos"
      - "/home/alex/Videos/archive"
    purpose: "Langzeitspeicherung für abgeschlossene Medienprojekte und Fotos."
    tags:
      - "archive"
      - "media"
      - "low-priority"
    review_frequency: "yearly"
    
  - name: "downloads-staging"
    paths:
      - "/home/alex/Downloads"
    purpose: "Temporärer Staging-Bereich für heruntergeladene Dateien."
    tags:
      - "temporary"
      - "staging"
    review_frequency: "weekly"
```

## Kernkonzepte des Zonen-Modells

*   **`name`**: Ein einzigartiger, lesbarer Bezeichner für die Zone.
*   **`paths`**: Eine Liste von einem oder mehreren absoluten Pfaden, die zu dieser Zone gehören.
*   **`purpose`**: Eine menschlich lesbare Beschreibung, die den Zweck der Zone für die KI und andere Benutzer erklärt.
*   **`tags`**: Eine Liste von Schlüsselwörtern, die die Eigenschaften der Zone beschreiben. Dies ist das primäre Mittel für die KI, um Zonen zu kategorisieren und zu filtern.
*   **`review_frequency`**: Eine empfohlene Häufigkeit (z. B. `weekly`, `monthly`, `yearly`, `never`), die angibt, wie oft die Inhalte der Zone aufgeräumt oder überprüft werden sollten.

## Best Practices

1.  **Beginne mit groben Zonen**: Starte mit 3-5 Hauptzonen, die deine Arbeitsweise widerspiegeln (z. B. `projects`, `archives`, `temporary`).
2.  **Nutze Tags für Details**: Verwende Tags, um die Priorität (`high-priority`) oder den Status (`active`, `readonly`) zu beschreiben, anstatt zu viele Zonen zu erstellen.
3.  **Halte den `purpose` klar**: Erkläre, *warum* diese Zone existiert. Dies ist entscheidender Kontext für die KI.
4.  **Sei realistisch bei der `review_frequency`**: Lege Frequenzen fest, die zu deinem Arbeitsablauf passen. Ein Download-Ordner braucht eine häufigere Überprüfung als ein Langzeitarchiv.
