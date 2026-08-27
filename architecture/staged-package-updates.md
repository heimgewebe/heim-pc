---
id: staged-package-updates
role: norm
status: canonical
last_reviewed: 2026-08-26
depends_on:
  - security
verifies_with:
  - scripts/staged_package_update.py
  - tests/test_staged_package_update.py
---

# Gestufte Paketupdates ohne Root-Netzfreigabe

## Zweck

APT- und Snap-Updates werden so vorbereitet, dass der bestehende privilegierte Grabowski-Broker **keinen IP-Netzzugriff** benötigt. Seine Einschränkung auf `AF_UNIX`/`AF_NETLINK` bleibt eine Sicherheitsgrenze und wird für Paketupdates nicht aufgeweicht.

Das Verfahren trennt drei Autoritäten:

1. **Stage:** Ein unprivilegierter Prozess darf Netzwerkzugriff benutzen, Repository-Metadaten verifizieren und Pakete herunterladen.
2. **Plan/Verify:** Ein lokaler Plan bindet exakte Artefakte, System- und Quellen-Preconditions sowie Root-Argumente an einen SHA-256-Digest. Der Plan selbst autorisiert nichts.
3. **Apply:** Der Controller lässt Root ausschließlich lokale Artefakte in einen root-eigenen Stagingbaum kopieren, liest deren Hashes zurück und startet den APT-Paketmanager danach in einer eigenen transienten System-Unit ohne IP-Netz; Snap wird über den lokalen `snapd`-Unix-Socket angewendet.

## Broker-sichtbarer Handoff

Der privilegierte Broker blendet `/run/user/<uid>` vollständig aus. Deshalb liegt der unprivilegierte Stage unter

`/home/alex/repos/.heim-pc-worktrees/.package-update-handoff/<plan-id>`.

Das ist **keine neue Broker-Freigabe**: `/home/alex/repos/.heim-pc-worktrees` ist bereits über `BindReadOnlyPaths` in den Broker eingebunden. Für den Broker bleibt der gesamte Handoff read-only; für den Nutzerprozess ist nur der verborgene Handoff-Unterbaum schreibbar. Vor jedem Planlauf wird die effektive Systemd-Konfiguration ausgewertet. Fehlt diese read-only Bindung, bricht der Plan fail-closed ab.

## APT

Der unprivilegierte Stage verwendet eigene `lists`, `archives` und Cachedateien ausschließlich im Handoff-Baum.

`apt-get update` läuft dort mit normaler APT-Signaturprüfung. Anschließend wird nur

`upgrade --with-new-pkgs --no-remove`

simuliert. Vor dem ersten Download löst APT für jeden Kandidaten über die authentifizierten Indizes URI-Identität, Größe und einen von APT gelieferten starken Hash auf. Zulässig sind ausschließlich SHA-256 und SHA-512; MD5, SHA-1, unbekannte Algorithmen und falsch lange Digests werden fail-closed verworfen. Die Summe der signierten Größen muss **vor** dem Download sowohl unter `max_download_bytes` als auch unter dem freien Staging-Speicher liegen. Erst danach wird heruntergeladen; jedes DEB muss bytegenau dem authentifizierten Hash-/Size-Eintrag entsprechen und wird zusätzlich über Paketname, Version, Architektur, Größe und einen lokalen SHA-256 gebunden.

`verify` vertraut weder dem unkeyed Plan-Digest noch vom Caller gelieferten Paketmetadaten als Provenienz. Es aktualisiert die kanonischen APT-Quellen erneut fail-closed, verlangt denselben signierten Upgrade-Kandidatensatz, löst die Repository-Hashes erneut auf und liest Paketidentität und Bytes jedes DEB zurück. Absolute oder aus dem jeweiligen Stage-Unterbaum ausbrechende Artefaktpfade sind verboten. Snap-Pläne müssen analog exakt der aktuell vom Store gemeldeten Pending-Refresh-Menge entsprechen.
Zusätzlich akzeptiert der privilegierte Verify-Pfad ausschließlich die zum Script gehörende kanonische `config/package-update-policy.v1.json`, das generierte Plan-ID-Format `YYYYMMDDTHHMMSSZ-<12 hex>` und exakt `<runtime_root>/<plan-id>/plan.json` als nicht-symlinkenden, user-eigenen Plancontainer. Damit können Caller weder über einen alternativen Policy-Pfad noch über `plan_id` den root-eigenen Stagingbaum umadressieren.

Der privilegierte Schritt führt **kein `apt-get update` und überhaupt keinen APT-Netzpfad** aus. Nach Root-Copy und vollständigem Hash-Readback wird zuerst exakt derselbe root-eigene DEB-Baum simuliert:

`dpkg --simulate --force-confold --install --recursive <root-owned-deb-dir>`

Nur bei erfolgreicher Simulation wird genau dieser Baum angewendet. Der Broker führt `dpkg` dabei **nicht selbst** aus, sondern startet über `systemd-run --system --wait --collect --pipe` eine plan-ID-gebundene transiente System-Unit. Deren Nutzprozess ist exakt:

`dpkg --force-confold --install --recursive <root-owned-deb-dir>`

Die Unit besitzt ein eigenes Netzwerk- und Mount-Namespace (`PrivateNetwork=yes`, `PrivateMounts=yes`) und überblendet `/run` mit einem privaten `tmpfs`. Systemd stellt seine Manager-Endpunkte in einem Service-Namespace teilweise erneut bereit; deshalb werden `/run/systemd/private` und `/run/dbus/system_bus_socket` zusätzlich explizit read-only durch `/dev/null` ersetzt. Damit kann selbst Root mit `CAP_DAC_OVERRIDE` dort keinen Socket öffnen. Andere Host-Sockets unter `/run` – etwa Docker, libvirt oder snapd – bleiben durch den privaten `/run`-Baum verborgen. `ProtectProc=invisible` und `ProcSubset=pid` minimieren die Prozesssicht; außerdem werden insbesondere `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, Netzwerk- und Modul-Capabilities aus dem Bounding Set entfernt. `RestrictAddressFamilies=AF_UNIX AF_NETLINK` und `IPAddressDeny=any` bleiben als weitere Schichten aktiv. Damit kann Paketcode weder direkt IP-Sockets öffnen noch über PID 1/System-D-Bus eine neue netzfähige Ausführung delegieren. `MemoryDenyWriteExecute` bleibt dagegen deaktiviert, damit legitime Paket-Maintainer-Skripte und Laufzeit-Trigger nicht unnötig gebrochen werden.

Die Paketmenge stammt weiterhin aus der signaturgeprüften APT-Simulation `upgrade --with-new-pkgs --no-remove`; der privilegierte Apply selbst hat jedoch keinerlei Beschaffungsfunktion. Damit gibt es keine Abhängigkeit von globalen oder veralteten APT-Indizes und keinen Archiv-Fetch, nicht einmal über einen lokalen APT-Acquire-Schritt. Zusätzlich bleibt der Broker selbst ohne `AF_INET`/`AF_INET6`, und die transiente Paket-Unit besitzt ebenfalls kein IP-Netz.

## Snap

`snap refresh --list` bestimmt unprivilegiert die angebotenen Revisionen. `snap download --revision ...` lädt pro Revision die `.snap`-Datei und die zugehörige Store-Assertion.

`verify` akzeptiert nicht nur das Pending-Tuple aus Name, Version und Revision. Für jede geplante Revision wird dieselbe `name + revision` über den lokalen snapd/Store-Pfad in einen frischen privaten Verify-Unterbaum erneut heruntergeladen; sowohl `.snap` als auch `.assert` müssen in Größe und SHA-256 byteidentisch mit den gestagten Artefakten sein. Damit kann ein caller-konstruierter Plan kein anderes gültig signiertes Snap/Assertion-Paar unter einer angebotenen Revision unterschieben.

Nach Root-Copy und Hash-Readback wird die so Store-gebundene Assertion mit `snap ack` bestätigt und die lokale Snap-Datei mit `snap install <file.snap>` eingespielt. `--dangerous` ist durch Policy und Verifikation verboten.

Falls eine konkrete Snap-Revision über diesen signierten lokalen Pfad nicht als Refresh akzeptiert wird, ist das ein terminaler Blocker für diese Revision. Es wird **nicht** auf `--dangerous` oder einen netzwerkgebundenen Root-Refresh ausgewichen.

## TOCTOU-Grenze

Der unprivilegierte Handoff bleibt bis zum Copy user-schreibbar. Deshalb darf Root niemals direkt aus diesem Baum installieren. Root sieht den Handoff nur read-only und kopiert die explizit geplanten Artefakte zuerst nach

`/var/lib/heim-pc/package-update-stages/<plan-id>`.

Der Controller vergleicht anschließend die Hashausgabe der root-eigenen Kopie vollständig mit dem Plan. Erst dieser Readback macht die Apply-Argumente verwendbar.

## Preconditions

Vor Apply müssen mindestens unverändert sein:

- SHA-256 von `/var/lib/dpkg/status`;
- aktive APT-Source- und Keyring-Dateien samt SHA-256;
- installierte Revision aller geplanten Snap-Consumer;
- Plan- und Policy-Digest;
- sämtliche Stage-Artefakte;
- die read-only Broker-Bindung des Handoff-Roots;
- Paketmanager-Liveness/Locks und die relevanten Operator-Ressourcen müssen separat vom Controller frisch geprüft werden.

Der Plan hat eine kurze maximale Lebensdauer. Jede Abweichung verlangt einen neuen Plan statt eines stillen Rebase des alten Plans.

## Postflight

`postflight` vergleicht jede geplante DEB-Version architekturgenau (`paket:architektur`) und jede Snap-Revision mit dem installierten Zustand, liest `reboot-required`, Kernservices und `nvidia-smi` zurück und schreibt ein Receipt in den Handoff-Stage. Damit werden Multiarch-Pakete wie `libssl3:amd64` und `libssl3:i386` nicht zu einer scheinbaren Doppelversion zusammengezogen.

Ein grünes Postflight-Receipt behauptet keine zukünftige Repository-Freshness und keinen bereits vollzogenen Neustart.

## Nicht-Ziele

- kein zweiter Root-Broker;
- keine Rootshell;
- kein `AF_INET`/`AF_INET6` im bestehenden Broker;
- keine neue Broker-Dateisystemfreigabe für diesen Mechanismus;
- kein `apt-get update` und kein `apt-get install` im privilegierten Schritt;
- kein `snap --dangerous`;
- kein Installieren aus alten globalen APT-Indizes;
- keine automatische Autorisierung allein durch einen erzeugten Plan.
