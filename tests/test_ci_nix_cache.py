from pathlib import Path
import json
import shutil
import subprocess

import pytest

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


def test_publisher_requires_explicit_repo_opt_in_before_runner_or_secrets():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    assert "workflow_dispatch:" not in workflow
    job_if = workflow.split("\njobs:\n  publish:\n    if: >-\n", 1)[1].split(
        "\n    runs-on:", 1
    )[0]
    conditions = [line.strip() for line in job_if.splitlines() if line.strip()]
    assert conditions[0] == "vars.CI_NIX_CACHE_PUBLISH_ENABLED == 'true' &&"
    assert "github.event.workflow_run.conclusion == 'success' &&" in conditions
    assert "github.event.workflow_run.event == 'push' &&" in conditions
    assert "github.event.workflow_run.head_branch == 'main' &&" in conditions
    assert "github.event.workflow_run.workflow_id == 351684660 &&" in conditions
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in conditions
    assert "secrets." not in job_if
    assert workflow.index("    if: >-") < workflow.index("    environment: ci-cache-publisher")


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
    assert "PUBLISHED_TRUSTED_CLOSURE" in workflow
    assert "PUBLISHED_SIGNED_PATH" not in workflow


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


def test_heavy_nix_installables_form_single_required_union():
    # Issue #167: one Nix solver invocation sees all 14 installables and can
    # schedule/deduplicate shared dependencies without skipping a former step.
    # Preserve the same exact-head Nix job and its early evaluation gates.
    workflow = CONSUMER.read_text(encoding="utf-8")
    _, separator, nix_job = workflow.partition("\n  nix:\n")
    assert separator, "required nix job is missing"
    label = "      - name: Build all mandatory Nix closures and VM checks in one union"
    _, found, after_label = nix_job.partition(label + "\n")
    assert found, "all mandatory expensive derivations must run in one union"
    union, proof_marker, _ = after_label.partition(
        "\n      - name: Prove untrusted signatures are rejected by substitution"
    )
    assert proof_marker, "the final signed-cache negative probe must still execute"
    assert union.startswith(
        "        run: >-\n"
        "          nix build --no-link --no-update-lock-file --print-out-paths --print-build-logs --max-jobs 2 --option cores 2\n"
    )
    assert union.count("--max-jobs 2 --option cores 2") == 1
    assert "--max-jobs 0" not in union and "--keep-going" not in union
    assert union.count("nix build --no-link --no-update-lock-file --print-out-paths --print-build-logs") == 1
    assert "|| true" not in union and "continue-on-error:" not in union
    installables = (
        ".#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel",
        ".#nixosConfigurations.heim-pc-vm.config.system.build.toplevel",
        ".#packages.x86_64-linux.physical-gate-proprietary-system",
        ".#packages.x86_64-linux.physical-gate-open-system",
        ".#packages.x86_64-linux.physical-gate-live-proprietary-iso",
        ".#packages.x86_64-linux.physical-gate-live-open-iso",
        ".#packages.x86_64-linux.physical-gate-live-inventory-iso",
        ".#packages.x86_64-linux.agent-microvm",
        ".#packages.x86_64-linux.agent-vsock-proof-microvm",
        ".#packages.x86_64-linux.trust-zone-host-system",
        ".#checks.x86_64-linux.integration",
        ".#checks.x86_64-linux.host-protection",
        ".#checks.x86_64-linux.firstboot-credentials",
        ".#checks.x86_64-linux.trust-zones",
    )
    assert len(installables) == 14
    for installable in installables:
        assert union.count(installable) == 1, installable
    assert union.count(".#") == len(installables)
    for old_step in (
        "Build storage, VM and physical-gate closures",
        "Build live-gate and inventory ISOs",
        "Build no-IP agent-zone closures",
        "Run scoped VM checks",
    ):
        assert f"- name: {old_step}" not in nix_job
    before_union = nix_job.split(label, 1)[0]
    assert "- name: Verify source identity" in before_union
    assert "- name: Evaluate complete flake without building checks" in before_union
    assert "- name: Prove evaluated Heim-PC contracts" in before_union
    assert "- name: Record heavy-derivation substitution plan" in before_union
    assert "timeout-minutes: 90" in before_union
    assert "runs-on: ubuntu-latest" in before_union
    assert "require-sigs = true" in before_union


def test_publisher_rejects_mismatched_signing_secret_before_copy_or_upload():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    assert f"CI_NIX_CACHE_PUBLIC_KEY: {CACHE_KEY}" in workflow
    derive = 'derived_public_key="$(nix key convert-secret-to-public < "$signing_key")"'
    check = 'if [[ "$derived_public_key" != "$CI_NIX_CACHE_PUBLIC_KEY" ]]; then'
    assert derive in workflow
    assert check in workflow
    assert workflow.index(derive) < workflow.index(check)
    assert workflow.index(check) < workflow.index("nix copy ")
    assert workflow.index(check) < workflow.index("rsync -r --ignore-existing")
    assert "refusing publication" in workflow


@pytest.mark.skipif(shutil.which("nix") is None, reason="Nix CLI unavailable")
def test_same_nix_signing_key_name_does_not_hide_mismatched_material():
    nix = shutil.which("nix")
    assert nix is not None

    def generate():
        return subprocess.run(
            [nix, "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "same-name-test-1"],
            check=True, capture_output=True, text=True,
        ).stdout

    def public(secret):
        return subprocess.run(
            [nix, "--extra-experimental-features", "nix-command", "key", "convert-secret-to-public"],
            input=secret, check=True, capture_output=True, text=True,
        ).stdout.strip()
    first, second = generate(), generate()
    expected = public(first)
    assert expected.startswith("same-name-test-1:")
    assert public(first) == expected
    assert public(second) != expected


def test_publisher_binds_stable_workflow_id_before_secrets():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    assert "github.event.workflow_run.workflow_id == 351684660" in workflow
    assert (
        "SOURCE_WORKFLOW_ID: "
        + chr(36) + "{{ github.event.workflow_run.workflow_id }}"
    ) in workflow
    assert 'test "$SOURCE_WORKFLOW_ID" = "351684660"' in workflow
    assert "github.event.workflow_run.path ==" not in workflow
    assert 'test "$SOURCE_WORKFLOW_PATH"' not in workflow
    assert workflow.index("Verify publisher source identity") < workflow.index(
        "Create signed append-only cache payload"
    )


def test_upload_origin_is_only_in_protected_publisher_environment():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    global_env = workflow.split("\nenv:\n", 1)[1].split("\njobs:\n", 1)[0]
    assert "CI_NIX_CACHE_SSH_HOST" not in global_env

    upload_step = workflow.split(
        "- name: Upload cache through restricted publisher key", 1
    )[1].split("- name: Verify public signed-cache readback", 1)[0]
    assert (
        "CI_NIX_CACHE_SSH_HOST: " + chr(36) + "{{ secrets.CI_CACHE_UPLOAD_SSH_HOST }}"
    ) in upload_step
    assert (
        "CI_NIX_CACHE_SSH_HOST_KEY: "
        + chr(36) + "{{ secrets.CI_CACHE_UPLOAD_SSH_HOST_KEY }}"
    ) in upload_step
    assert "vars.CI_CACHE_UPLOAD_SSH_HOST" not in upload_step
    assert "vars.CI_CACHE_UPLOAD_SSH_HOST_KEY" not in upload_step
    assert 'test -n "$CI_NIX_CACHE_SSH_HOST"' in upload_step
    assert 'test -n "$CI_NIX_CACHE_SSH_HOST_KEY"' in upload_step
    assert "StrictHostKeyChecking=yes" in upload_step
    assert "environment: ci-cache-publisher" in workflow


def test_publisher_recovers_entire_signed_closure_from_fresh_empty_cache():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    tail = workflow[workflow.index("      - name: Verify public signed-cache readback"):]
    assert "require-sigs = true" in tail
    assert "fallback = false" in tail
    assert "trusted-public-keys = $CI_NIX_CACHE_PUBLIC_KEY" in tail
    assert "substituters = $CI_NIX_CACHE_URL" in tail
    assert 'test ! -e "$readback_cache_dir"' in tail
    assert "nix copy " in tail
    assert '--from "$CI_NIX_CACHE_URL"' in tail
    assert '--to "file://$readback_cache_dir"' in tail
    assert '"$OLLAMA_PATH" "$LLAMA_CPP_PATH"' in tail
    assert 'nix path-info --recursive --store "file://$readback_cache_dir"' in tail
    assert 'nix path-info --recursive "$OLLAMA_PATH" "$LLAMA_CPP_PATH"' in tail
    assert 'cmp -s "$expected_closure" "$remote_closure"' in tail
    # Copying between binary caches does not by itself enforce signatures.
    # Verify the full fetched closure under the exact trusted CI key.
    verify = 'nix store verify --store "file://$readback_cache_dir" --recursive'
    assert verify in tail
    assert tail.index('nix copy --from "$CI_NIX_CACHE_URL"') < tail.index(verify)
    assert tail.index(verify) < tail.index("PUBLISHED_TRUSTED_CLOSURE=")
    assert "--no-trust" not in tail
    assert "--no-contents" not in tail
    assert "PUBLISHED_TRUSTED_CLOSURE" in tail
    assert "PUBLISHED_TRUSTED_SUBSTITUTION" not in tail
    assert "nix-store --delete" not in tail
    assert "--no-check-sigs" not in tail
    assert "require-sigs = false" not in tail