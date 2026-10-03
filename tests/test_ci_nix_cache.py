from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / ".github" / "workflows" / "heim-pc-nix.yml"
PUBLISHER = ROOT / ".github" / "workflows" / "heim-pc-nix-cache-publish.yml"
PRODUCTION_TRUST = ROOT / "nixos" / "production" / "trust-contract-v1.json"
SIGNATURE_PROBE = ROOT / "scripts" / "ci" / "check_nix_cache_signature_rejection.sh"

CACHE_URL = "https://commonserver.tail6dbb90.ts.net:10000/nix-cache"
CACHE_KEY = (
    "heim-pc-ci-cache-20260923-1:"
    "fDffoLuvBMGVo8JKRR7uY7EmJPawIsKXuB5OBswBdIo="
)


def test_ci_consumer_keeps_signed_fallback_cache_separate_from_production():
    workflow = CONSUMER.read_text(encoding="utf-8")

    assert f"extra-substituters = {CACHE_URL}" in workflow
    assert f"extra-trusted-public-keys = {CACHE_KEY}" in workflow
    assert "require-sigs = true" in workflow
    assert "fallback = true" in workflow
    assert "accept-flake-config = true" not in workflow
    assert "require-sigs = false" not in workflow
    assert "CI_CACHE_NIX_SIGNING_KEY" not in workflow
    assert "CI_CACHE_UPLOAD_SSH_KEY" not in workflow

    trust = json.loads(PRODUCTION_TRUST.read_text(encoding="utf-8"))["nix"]
    assert trust["substituters"] == ["https://cache.nixos.org/"]
    assert trust["trusted_substituters"] == ["https://cache.nixos.org/"]
    assert trust["trusted_public_keys"] == [
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ]
    assert trust["require_sigs"] is True
    assert trust["accept_flake_config"] is False


def test_publisher_is_main_only_and_secrets_never_enter_pull_request_workflow():
    workflow = PUBLISHER.read_text(encoding="utf-8")

    assert "workflow_run:" in workflow
    assert "github.event.workflow_run.event == 'push'" in workflow
    assert "github.event.workflow_run.head_branch == 'main'" in workflow
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in workflow
    assert "environment: ci-cache-publisher" in workflow
    assert "pull_request:" not in workflow
    assert "CI_CACHE_NIX_SIGNING_KEY_B64" in workflow
    assert "CI_CACHE_UPLOAD_SSH_KEY_B64" in workflow
    assert "persist-credentials: false" in workflow


def test_publisher_resolves_exact_heavy_derivations_and_signs_before_upload():
    workflow = PUBLISHER.read_text(encoding="utf-8")

    assert "nix derivation show --recursive" in workflow
    assert "-ollama-0.32.3.drv" in workflow
    assert "-llama-cpp-9190.drv" in workflow
    assert "nix copy --no-recursive" not in workflow
    assert "nix copy \\" in workflow
    assert 'ollama_drv_key="${ollama_drvs[0]}"' in workflow
    assert 'llama_drv_key="${llama_drvs[0]}"' in workflow
    assert 'ollama_drv="/nix/store/$ollama_drv_key"' in workflow
    assert 'llama_drv="/nix/store/$llama_drv_key"' in workflow
    assert "?secret-key=$signing_key" in workflow
    assert "rsync -r --ignore-existing" in workflow
    assert "StrictHostKeyChecking=yes" in workflow
    assert "PUBLISHED_SIGNED_PATH" in workflow


def test_consumer_keeps_all_existing_nix_gates_and_invalid_signature_probe():
    workflow = CONSUMER.read_text(encoding="utf-8")

    required = [
        ".#checks.x86_64-linux.profile-contract",
        ".#checks.x86_64-linux.supply-chain-trust",
        ".#checks.x86_64-linux.nix-lifecycle-contract",
        ".#checks.x86_64-linux.recovery-readiness-contract",
        ".#checks.x86_64-linux.intentional-break-rejected",
        ".#checks.x86_64-linux.agent-zone-contract",
        ".#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel",
        ".#nixosConfigurations.heim-pc-vm.config.system.build.toplevel",
        ".#packages.x86_64-linux.physical-gate-proprietary-system",
        ".#packages.x86_64-linux.physical-gate-open-system",
        ".#packages.x86_64-linux.physical-gate-live-proprietary-iso",
        ".#packages.x86_64-linux.physical-gate-live-open-iso",
        ".#packages.x86_64-linux.agent-microvm",
        ".#packages.x86_64-linux.agent-vsock-proof-microvm",
        ".#packages.x86_64-linux.trust-zone-host-system",
        ".#checks.x86_64-linux.integration",
        ".#checks.x86_64-linux.firstboot-credentials",
        ".#checks.x86_64-linux.trust-zones",
    ]
    for installable in required:
        assert installable in workflow

    assert "workflow_dispatch:" in workflow
    assert "bash scripts/ci/check_nix_cache_signature_rejection.sh" in workflow
    assert "--no-check-sigs" not in workflow

    probe = SIGNATURE_PROBE.read_text(encoding="utf-8")
    assert "heim-pc-ci-cache-untrusted-probe-1" in probe
    assert "substituters = http://127.0.0.1:$PROBE_PORT" in probe
    assert "require-sigs = true" in probe
    assert "max-jobs = 0" in probe
    assert 'nix-store --realise "$drv"' in probe
    assert "INVALID_SIGNATURE_REJECTED=true" in probe
    assert "TRUSTED_SIGNATURE_ACCEPTED=true" in probe
    assert 'grep -Fq "not signed by any of the keys in"' in probe
    assert 'grep -Fq "trusted-public-keys"' in probe
    assert 'test ! -e "$out"' in probe
    assert 'grep -q "^CA:" "$narinfo"' in probe
    assert 'grep -q "^Sig: heim-pc-ci-cache-untrusted-probe-1:" "$narinfo"' in probe
    assert 'test "$(grep -c "^Sig:" "$narinfo")" -eq 1' in probe
    assert 'test_key="$(cat /probe/untrusted.pub)"' in probe
    assert "nix copy --no-recursive --from" not in probe
    assert "require-sigs = false" not in probe
    assert 'grep -Eiq "signature|trusted key|trusted public key|not signed"' not in probe