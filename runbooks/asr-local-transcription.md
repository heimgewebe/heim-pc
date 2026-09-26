---
operational_runbook:
  contract: operational-runbook.v1
  id: heim-pc.asr-host-integration
  status: active
  title: Heim-PC ASR host integration
  applies_to:
    operations: [audio.transcribe, asr-host-cutover]
    platforms: [linux]
    components: [heim-pc, asr]
  evidence_refs: [architecture/asr-engine.md, manifest/operator-entry.v1.json]
  does_not_establish: [routing_authority, policy_authority, cloud_cost_authorization, current_runtime_state]
---

# ASR host integration

Die fachliche und technische ASR-Policy liegt ausschließlich in `heimgewebe/asr`.
Das kanonische Runbook ist `${HOME}/repos/asr/runbooks/asr-local-transcription.md`.
Dieses Heim-PC-Runbook beschreibt nur Host-Kompatibilität.

## 1. Native Oberfläche vor Host-Locator prüfen

Vor dem host-local Schritt zuerst eine bereits veröffentlichte native typed Grabowski-Oberfläche verwenden, wenn sie den Auftrag erfüllt. Nur wenn keine solche Oberfläche passt, den installierten Maschinenvertrag über die host-local Capability-Auflösung lesen. Ein `blocked` ist kein Miss und darf nicht durch einen Ersatzpfad umgangen werden. Nur ein explizites `not_found` darf zu einer bereits deklarierten Spezialroute weiterführen:

`grabowski_host_capability_resolve(intent="audio.transcribe")`

Die aufgelöste Authority muss `heimgewebe_asr_open_engine` sein und auf `${HOME}/repos/asr` zeigen. Diese Prüfung erteilt weder Engine- noch Cloud-Autorität.
## Host-Cutover

1. `grabowski_host_capability_resolve(intent="audio.transcribe")` lesen.
2. Generischen `doctor` unter `${HOME}/repos/asr/scripts/asr_engine.py` ausführen.
3. Wenn nur der alte Hostcache vorhanden ist, **nicht setup ausführen**.
4. Alten Cache/State atomar nach `~/.local/{cache,state}/heimgewebe/asr` verschieben.
5. Alte Hostpfade optional als Symlink auf den neuen Root erhalten.
6. Generischen `doctor` erneut ausführen.
7. Eine reale lokale Transkription als Dogfood prüfen.

## Kompatibilität

`${HOME}/repos/heim-pc/scripts/asr_engine.py` ist nur ein Exec-Wrapper zum
generischen Einstieg. Er besitzt keine Engine-, Routing-, Kosten- oder
Transcript-Semantik.