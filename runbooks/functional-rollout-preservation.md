# Funktionale Bestandsgarantie bei Rollouts

Die bestehende NixOS-Funktionskarte und der Closure-Strukturvergleich in
[README](../README.md#dauerhafte-integrationen-und-rollout-vergleich) bleiben die
führende Orientierung. Keine zweite Registry und keine pauschale Boot-Sperre.

## SSH-Cockpit als Referenzfall

- Source: `nixos/system/modules/ssh-cockpit-autocopy.nix` und sein gleichnamiges
  Quellverzeichnis. Die Generation liefert tmux, Watcher, manuelle Kopierhilfe
  und `copy-off`; der globale Hook ist auf alex begrenzt.
- Die bekannte lokale Altdatei wird durch die nicht bootkritische User-Unit
  `heim-pc-tmux-autocopy-migration.service` einmalig migriert. Individuell
  veränderte Dateien bleiben erhalten und sind bei der Abnahme separat zu
  prüfen. Die erhaltene Altdatei und die alten Helfer ermöglichen Rollback.
  Laufende Sitzungen werden nicht beendet; neue Server bzw. Sitzungen
  müssen den tatsächlich verwendeten Hook nachweisen.
- Regression: `python3 tests/test_ssh_cockpit_autocopy.py`. Der Linux-PTY-Test
  prüft die tatsächlich ausgesendete OSC52-Sequenz an zwei gleichzeitig
  verbundenen Clients, normales Ergebnis,
  historische sensitive Ausgabe, keine Ausgabe, Eingabe ohne Ausführung und
  expliziten Opt-out. Ein übersprungener PTY-Test ist kein Funktionsnachweis.
- Produktiv: Generation und Quellrevision vergleichen, den neuen Hook und
  die Migration prüfen, mit neutralem Ergebnis OSC52 über einen isolierten
  PTY nachweisen. Der reale iPad-Paste bleibt eine separate Client-Abnahme.
  Keine Terminalhistorie des Benutzers auslesen.

## Übertragung auf andere Funktionen

Neue dauerhafte Integrationen gehören in die bestehende deklarative
Authority. Vor Rollout den vorhandenen Closure-Strukturvergleich verwenden;
betroffene Funktionen mit kleinen reproduzierbaren Probes absichern. Nach
Aktivierung aktive und regulär bootfähige Generation sowie wesentliche
Nutzerwege prüfen. Kritische Fehler erfordern Recovery; nichtkritische
Regressionsbefunde eine gezielte Reparatur. Eine grüne CI, ein Health-Check
oder ein Merge ersetzen die produktive Abnahme nicht. Bestehende
OneShot-/Approved-Mechanismen unverändert wiederverwenden.
