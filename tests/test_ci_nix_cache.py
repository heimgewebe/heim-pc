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
    assert 'closure_paths=( "$OLLAMA_PATH" "$LLAMA_CPP_PATH" )' in tail
    assert 'nix path-info --recursive "${closure_paths[@]}"' in tail
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


def test_consumer_distinguishes_nix_cache_protocol_from_http_health():
    workflow = CONSUMER.read_text(encoding="utf-8")
    _, marker, remainder = workflow.partition(
        "      - name: Report CI-only signed-cache trust\n"
    )
    assert marker, "missing signed-cache readiness step"
    report, end, _ = remainder.partition(
        "      - name: Evaluate complete flake without building checks\n"
    )
    assert end, "readiness step must precede normal Nix evaluation"
    # A 200 from health.txt alone says nothing about the Nix binary-cache
    # protocol or whether any signed output is present.
    assert '"$CI_NIX_CACHE_URL/nix-cache-info"' in report
    assert "awk " in report
    # Test the normalized Nix cache-info StoreDir parser, not a raw whole-line literal.
    assert '== "StoreDir"' in report
    assert 'v != "/nix/store"' in report
    assert "--max-filesize 4096" in report
    assert "CI_NIX_CACHE_PROTOCOL=available" in report
    assert "CI_NIX_CACHE_PROTOCOL=unavailable" in report
    assert 'curl --fail' in report
    assert '"$CI_NIX_CACHE_URL/health.txt"' not in report
    assert "CI_NIX_CACHE_HEALTH=available" not in report
    # This diagnostic is never an admission gate or an unsigned-cache bypass.
    assert "require-sigs = false" not in report
    assert "--no-check-sigs" not in report
    assert "fallback=true" in report


@pytest.mark.parametrize(
    ("probe_mode", "expected"),
    [
        ("not_found", "unavailable"),
        ("wrong_store_dir", "unavailable"),
        ("missing_store_dir", "unavailable"),
        ("valid_protocol", "available"),
        ("valid_protocol_padded", "available"),
        ("valid_protocol_tabbed", "available"),
        ("conflicting_store_dirs", "unavailable"),
        ("conflicting_store_dirs_padded", "unavailable"),
        ("duplicated_store_dir", "unavailable"),
        ("duplicated_store_dir_padded", "unavailable"),
    ],
)
def test_consumer_cache_protocol_probe_runtime(tmp_path, probe_mode, expected):
    """Exercise the actual Actions run fragment without reaching a network."""
    import os

    workflow = CONSUMER.read_text(encoding="utf-8")
    _, marker, tail = workflow.partition(
        "      - name: Report CI-only signed-cache trust\n"
    )
    assert marker
    body, end, _ = tail.partition(
        "      - name: Evaluate complete flake without building checks\n"
    )
    assert end and body.startswith("        run: |\n")
    script = "\n".join(
        line[10:] if line.strip() else ""
        for line in body.split("        run: |\n", 1)[1].splitlines()
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nix = bin_dir / "nix"
    nix.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo 'nix 2.35.2'; exit 0; fi\n"
        "if [ \"$1\" = \"config\" ] && [ \"$2\" = \"show\" ]; then\n"
        "  echo 'require-sigs = true'\n"
        "  echo 'fallback = true'\n"
        "  echo 'substituters = https://cache.nixos.org/'\n"
        "  echo 'trusted-public-keys = cache.nixos.org-1:test'\n"
        "  exit 0\n"
        "fi\n"
        "exit 31\n",
        encoding="utf-8",
    )
    curl = bin_dir / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *'/nix-cache-info'*) ;;\n"
        "  *) exit 41 ;;\n"
        "esac\n"
        "case \"$PROBE_MODE\" in\n"
        "  not_found) exit 22 ;;\n"
        "  wrong_store_dir) printf 'StoreDir: /tmp/invalid\\n'; exit 0 ;;\n"
        "  missing_store_dir) printf 'WantMassQuery: 1\\n'; exit 0 ;;\n"
        "  valid_protocol) printf 'StoreDir: /nix/store\\nWantMassQuery: 1\\n'; exit 0 ;;\n"
        "  valid_protocol_padded) printf 'StoreDir:  /nix/store  \\nWantMassQuery: 1\\n'; exit 0 ;;\n"
        "  valid_protocol_tabbed) printf 'StoreDir:\t/nix/store\t\\nWantMassQuery: 1\\n'; exit 0 ;;\n"
        "  conflicting_store_dirs) printf 'StoreDir: /nix/store\\nStoreDir: /tmp/invalid\\n'; exit 0 ;;\n"
        "  conflicting_store_dirs_padded) printf 'StoreDir:  /nix/store  \\nStoreDir:  /tmp/invalid  \\n'; exit 0 ;;\n"
        "  duplicated_store_dir) printf 'StoreDir: /nix/store\\nStoreDir: /nix/store\\n'; exit 0 ;;\n"
        "  duplicated_store_dir_padded) printf 'StoreDir:  /nix/store  \\nStoreDir:  /nix/store  \\n'; exit 0 ;;\n"
        "  *) exit 42 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    nix.chmod(0o700)
    curl.chmod(0o700)
    env = dict(os.environ)
    env.update(
        PATH=f"{bin_dir}:{os.environ['PATH']}",
        CI_NIX_CACHE_URL="https://example.invalid/nix-cache",
        RUNNER_TEMP=str(tmp_path),
        PROBE_MODE=probe_mode,
    )
    run = subprocess.run(
        ["bash", "-e", "-c", script],
        env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    assert run.returncode == 0, run.stderr
    assert f"CI_NIX_CACHE_PROTOCOL={expected}" in run.stdout
    assert not list(tmp_path.glob("heim-pc-ci-cache-info.*"))


def _cache_publisher_upload_script():
    """Extract the actual publisher shell step, excluding secret declarations."""
    workflow = PUBLISHER.read_text(encoding="utf-8")
    _, marker, tail = workflow.partition(
        "      - name: Upload cache through restricted publisher key\n"
    )
    assert marker
    step, end, _ = tail.partition(
        "      - name: Verify public signed-cache readback\n"
    )
    assert end
    _, marker, script = step.partition("        run: |\n")
    assert marker
    return "\n".join(
        line[10:] if line.strip() else ""
        for line in script.splitlines()
    )


def test_cache_upload_publishes_nar_bytes_before_signed_narinfo():
    """Signed narinfo must not become visible before its referenced NAR."""
    script = _cache_publisher_upload_script()
    payload = "rsync -r --ignore-existing --exclude='*.narinfo'"
    readback = "curl --fail --silent --show-error"
    metadata = "rsync -r --ignore-existing --include='*.narinfo' --exclude='*'"
    assert script.count("rsync -r --ignore-existing") == 2
    assert payload in script
    assert readback in script
    assert metadata in script
    assert script.index(payload) < script.index(readback) < script.index(metadata)
    assert "--proto '=https'" in script
    assert "StrictHostKeyChecking=yes" in script
    assert "UserKnownHostsFile=$known_hosts" in script
    assert "rsync -r --delete" not in script
    assert "--inplace" not in script


@pytest.mark.parametrize("fail_first", [True, False])
def test_cache_upload_shell_never_publishes_metadata_after_failed_payload(
    tmp_path, fail_first,
):
    """Run the actual Actions step with an isolated, non-network rsync stub."""
    import base64
    import os

    script = _cache_publisher_upload_script()
    cache = tmp_path / "ci-nix-cache"
    cache.mkdir()
    (cache / "nar").mkdir()
    (cache / "nar" / "dummy.nar.xz").write_bytes(b"dummy NAR payload")
    (cache / "dummy.narinfo").write_bytes(b"StorePath: /nix/store/dummy\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    rsync = binaries / "rsync"
    rsync.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$RSYNC_ARGS_LOG\"\n"
        "if [ \"$FAIL_FIRST\" = 1 ] && [ \"$(wc -l < \"$RSYNC_ARGS_LOG\")\" -eq 1 ]; then\n"
        "  exit 23\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    rsync.chmod(0o700)
    curl = binaries / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *'/nar/dummy.nar.xz'*) cat \"$RUNNER_TEMP/ci-nix-cache/nar/dummy.nar.xz\" ;;\n"
        "  *'--write-out'*'/dummy.narinfo'*) printf '404' ;;\n"
        "  *'/dummy.narinfo'*) cat \"$RUNNER_TEMP/ci-nix-cache/dummy.narinfo\" ;;\n"
        "  *) exit 44 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    curl.chmod(0o700)
    log = tmp_path / "rsync-args.log"
    env = dict(os.environ)
    env.update(
        PATH=f"{binaries}:{os.environ['PATH']}",
        RUNNER_TEMP=str(tmp_path),
        UPLOAD_KEY_B64=base64.b64encode(b"test-only-ssh-key").decode("ascii"),
        CI_NIX_CACHE_SSH_HOST="unreachable.example.invalid",
        CI_NIX_CACHE_SSH_HOST_KEY="ssh-ed25519 TEST-ONLY-NOT-REAL",
        CI_NIX_CACHE_URL="https://cache.example.invalid/nix-cache",
        RSYNC_ARGS_LOG=str(log),
        FAIL_FIRST="1" if fail_first else "0",
    )
    outcome = subprocess.run(
        ["bash", "-e", "-c", script],
        env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert len(calls) == (1 if fail_first else 2)
    assert "--exclude=*.narinfo" in calls[0]
    if fail_first:
        assert outcome.returncode != 0
        assert not any("--include=*.narinfo" in call for call in calls)
    else:
        assert outcome.returncode == 0, outcome.stderr
        assert "--include=*.narinfo" in calls[1]
        assert "--exclude=*" in calls[1]
    assert not (tmp_path / "ci-nix-cache-upload-key").exists()
    assert not (tmp_path / "ci-nix-cache-known-hosts").exists()


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync CLI unavailable")
def test_cache_upload_real_rsync_filter_is_payload_first_and_append_only(tmp_path):
    """Use the actual workflow filters against an entirely local fixture cache."""
    import shlex

    commands = [
        line.strip().removesuffix("\\").strip()
        for line in _cache_publisher_upload_script().splitlines()
        if line.strip().startswith("rsync -r --ignore-existing")
    ]
    assert len(commands) == 2
    argv = [shlex.split(command)[1:] for command in commands]

    cache = tmp_path / "signed-cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nar" / "test.nar.xz").write_bytes(b"archived NAR fixture")
    narinfo = cache / "fixture.narinfo"
    narinfo.write_bytes(b"Sig: test-key:signature-fixture\n")
    (cache / "nix-cache-info").write_bytes(b"StoreDir: /nix/store\n")
    destination = tmp_path / "remote"
    destination.mkdir()

    def transfer(filters):
        subprocess.run(
            ["rsync", *filters, str(cache) + "/", str(destination) + "/"],
            check=True, capture_output=True, text=True, timeout=10,
        )

    transfer(argv[0])
    assert (destination / "nar" / "test.nar.xz").read_bytes() == (
        b"archived NAR fixture"
    )
    assert (destination / "nix-cache-info").is_file()
    assert not (destination / "fixture.narinfo").exists()

    transfer(argv[1])
    assert (destination / "fixture.narinfo").read_bytes() == (
        b"Sig: test-key:signature-fixture\n"
    )
    narinfo.write_bytes(b"Sig: attacker-key:replacement\n")
    (cache / "nar" / "test.nar.xz").write_bytes(b"changed NAR")
    transfer(argv[0])
    transfer(argv[1])
    assert (destination / "nar" / "test.nar.xz").read_bytes() == (
        b"archived NAR fixture"
    )
    assert (destination / "fixture.narinfo").read_bytes() == (
        b"Sig: test-key:signature-fixture\n"
    )


def test_cache_upload_rejects_preexisting_remote_nar_mismatch_before_narinfo(tmp_path):
    """A successful append-only upload must not endorse stale remote bytes."""
    import base64
    import os

    script = _cache_publisher_upload_script()
    cache = tmp_path / "ci-nix-cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nar" / "sample.nar.xz").write_bytes(b"VALID NAR")
    (cache / "sample.narinfo").write_text(
        "URL: nar/sample.nar.xz\nFileHash: sha256:synthetic\n", encoding="utf-8"
    )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    rsync = bindir / "rsync"
    rsync.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$RSYNC_ARGS_LOG\"\n"
        "case \" $* \" in\n"
        "  *' --checksum --dry-run '*)\n"
        "    printf '>fcsT...... nar/sample.nar.xz\\n'\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    rsync.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text("#!/bin/sh\nprintf 'PARTIAL'\n", encoding="utf-8")
    curl.chmod(0o700)
    calls_path = tmp_path / "calls.log"
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{os.environ['PATH']}",
        RUNNER_TEMP=str(tmp_path),
        UPLOAD_KEY_B64=base64.b64encode(b"test-only-ssh-key").decode("ascii"),
        CI_NIX_CACHE_SSH_HOST="unreachable.example.invalid",
        CI_NIX_CACHE_SSH_HOST_KEY="ssh-ed25519 TEST-ONLY-NOT-REAL",
        CI_NIX_CACHE_URL="https://cache.example.invalid/nix-cache",
        RSYNC_ARGS_LOG=str(calls_path),
    )
    outcome = subprocess.run(
        ["bash", "-e", "-c", script],
        env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    calls = calls_path.read_text(encoding="utf-8").splitlines()
    assert outcome.returncode != 0, "mismatched remote NAR may not be published"
    assert len(calls) == 1
    assert "--exclude=*.narinfo" in calls[0]
    assert not any("--include=*.narinfo" in call for call in calls)


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync CLI unavailable")
def test_cache_upload_remote_payload_checksum_detects_stale_existing_bytes(tmp_path):
    """Forced rrsync -no-overwrite hides stale receiver bytes even in dry-run."""
    script = _cache_publisher_upload_script()
    assert "curl --fail --silent --show-error" in script
    source = tmp_path / "ci-nix-cache"
    destination = tmp_path / "remote"
    (source / "nar").mkdir(parents=True)
    (destination / "nar").mkdir(parents=True)
    local_bytes = b"verified NAR payload bytes"
    (source / "nar" / "fixture.nar.xz").write_bytes(local_bytes)
    remote_path = destination / "nar" / "fixture.nar.xz"
    audit_argv = [
        "rsync", "-r", "--checksum", "--dry-run", "--itemize-changes", "--ignore-existing",
        "--exclude=*.narinfo", str(source) + "/", str(destination) + "/",
    ]
    upload_argv = [
        "rsync", "-r", "--ignore-existing", "--exclude=*.narinfo",
        str(source) + "/", str(destination) + "/",
    ]
    for stale in (b"PARTIAL", b"X" * len(local_bytes)):
        remote_path.write_bytes(stale)
        # The first upload pass skips existing files even when they are wrong.
        skipped = subprocess.run(
            upload_argv, capture_output=True, text=True, timeout=10, check=False,
        )
        assert skipped.returncode == 0, skipped.stderr
        assert remote_path.read_bytes() == stale
        audit = subprocess.run(
            audit_argv, capture_output=True, text=True, timeout=10, check=False,
        )
        assert audit.returncode == 0, audit.stderr
        assert audit.stdout == "", "receiver-side --ignore-existing hides the mismatch"
        assert remote_path.read_bytes() == stale, "audit may not repair or mutate"
    remote_path.write_bytes(local_bytes)
    audit = subprocess.run(
        audit_argv, capture_output=True, text=True, timeout=10, check=False,
    )
    assert audit.returncode == 0, audit.stderr
    assert audit.stdout == "", "verified remote bytes must not block publication"


def test_cache_upload_refuses_remote_nar_mismatch_when_rrsync_skips_audit(tmp_path):
    """Server-enforced --ignore-existing makes receiver-side dry-run blind."""
    import base64
    import os

    script = _cache_publisher_upload_script()
    cache = tmp_path / "ci-nix-cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nar" / "test.nar.xz").write_bytes(b"VALID FULL NAR")
    (cache / "test.narinfo").write_bytes(b"StorePath: /nix/store/test\n")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    rsync = bindir / "rsync"
    rsync.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$RSYNC_ARGS_LOG\"\n"
        "# Mimic forced rrsync -no-overwrite: existing remote NAR is skipped\n"
        "# even for a receiver-side checksum dry-run.\n"
        "exit 0\n", encoding="utf-8",
    )
    rsync.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$CURL_ARGS_LOG\"\n"
        "printf 'PARTIAL'\n",
        encoding="utf-8",
    )
    curl.chmod(0o700)
    rsync_log = tmp_path / "rsync-args.log"
    curl_log = tmp_path / "curl-args.log"
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{os.environ['PATH']}",
        RUNNER_TEMP=str(tmp_path),
        UPLOAD_KEY_B64=base64.b64encode(b"test-ssh-key").decode(),
        CI_NIX_CACHE_SSH_HOST="unreachable.example.invalid",
        CI_NIX_CACHE_SSH_HOST_KEY="ssh-ed25519 TEST",
        CI_NIX_CACHE_URL="https://cache.example.invalid/nix-cache",
        RSYNC_ARGS_LOG=str(rsync_log),
        CURL_ARGS_LOG=str(curl_log),
    )
    result = subprocess.run(
        ["bash", "-e", "-c", script], env=env,
        capture_output=True, text=True, timeout=10, check=False,
    )
    calls = rsync_log.read_text(encoding="utf-8").splitlines()
    assert result.returncode != 0, "stale published NAR must abort"
    assert curl_log.is_file(), "must compare authenticated public NAR bytes"
    assert "/nar/test.nar.xz" in curl_log.read_text(encoding="utf-8")
    assert not any("--include=*.narinfo" in call for call in calls)


@pytest.mark.parametrize("second_mode", ["ok", "stale", "http_error"])
def test_cache_upload_reads_all_nars_and_blocks_bad_second_response(tmp_path, second_mode):
    """Valid first NAR must not permit narinfo if a later readback is bad."""
    import base64
    import os

    script = _cache_publisher_upload_script()
    cache = tmp_path / "ci-nix-cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nar" / "a.nar.xz").write_bytes(b"NAR-A")
    (cache / "nar" / "b.nar.zst").write_bytes(b"NAR-B")
    (cache / "example.narinfo").write_bytes(b"Sig: fixture\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    rsync = bindir / "rsync"
    rsync.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$RSYNC_ARGS_LOG\"\n"
        "exit 0\n", encoding="utf-8",
    )
    rsync.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$CURL_ARGS_LOG\"\n"
        "case \"$*\" in\n"
        "  *'/nar/a.nar.xz'*) printf 'NAR-A' ;;\n"
        "  *'/nar/b.nar.zst'*)\n"
        "    case \"$SECOND_MODE\" in\n"
        "      stale) printf 'WRONG' ;;\n"
        "      http_error) printf 'NAR-B'; exit 22 ;;\n"
        "      ok) printf 'NAR-B' ;;\n"
        "      *) exit 15 ;;\n"
        "    esac ;;\n"
        "  *'/example.narinfo'*)\n"
        "    case \"$*\" in\n"
        "      *'--write-out'*) printf '404' ;;\n"
        "      *) cat \"$RUNNER_TEMP/ci-nix-cache/example.narinfo\" ;;\n"
        "    esac ;;\n"
        "  *) exit 17 ;;\n"
        "esac\n", encoding="utf-8",
    )
    curl.chmod(0o700)
    rsync_log = tmp_path / "rsync-args.log"
    curl_log = tmp_path / "curl-args.log"
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{os.environ['PATH']}",
        RUNNER_TEMP=str(tmp_path),
        UPLOAD_KEY_B64=base64.b64encode(b"test-only-ssh-key").decode("ascii"),
        CI_NIX_CACHE_SSH_HOST="unreachable.example.invalid",
        CI_NIX_CACHE_SSH_HOST_KEY="ssh-ed25519 TEST-ONLY-NOT-REAL",
        CI_NIX_CACHE_URL="https://cache.example.invalid/nix-cache",
        RSYNC_ARGS_LOG=str(rsync_log),
        CURL_ARGS_LOG=str(curl_log),
        SECOND_MODE=second_mode,
    )
    result = subprocess.run(
        ["bash", "-e", "-c", script], env=env,
        capture_output=True, text=True, timeout=10, check=False,
    )
    calls = rsync_log.read_text(encoding="utf-8").splitlines()
    gets = curl_log.read_text(encoding="utf-8").splitlines()
    assert len(gets) == (4 if second_mode == "ok" else 2), gets
    assert "--proto =https" in gets[0] and "--proto =https" in gets[1]
    assert "/nar/a.nar.xz" in gets[0] and "/nar/b.nar.zst" in gets[1]
    if second_mode == "ok":
        assert "/example.narinfo" in gets[2] and "/example.narinfo" in gets[3]
    assert ("--include=*.narinfo" in "\n".join(calls)) == (second_mode == "ok")
    if second_mode == "ok":
        assert result.returncode == 0, result.stderr
        assert len(calls) == 2
    else:
        assert result.returncode != 0
        assert len(calls) == 1


@pytest.mark.parametrize("remote_mode", [
    "mismatched", "present_same", "missing_then_published",
    "http_error", "missing_after_upload", "race_other_metadata",
])
def test_cache_upload_authenticates_preexisting_and_new_signed_narinfo(
    tmp_path, remote_mode,
):
    """A retained signed .narinfo must not be mistaken for this build's output.

    Run the real Actions shell step. The SSH publisher is append-only, and
    independent HTTPS reads simulate the cache consumer. No network is used.
    """
    import base64
    import os

    script = _cache_publisher_upload_script()
    cache = tmp_path / "ci-nix-cache"
    (cache / "nar").mkdir(parents=True)
    (cache / "nar" / "sample.nar.xz").write_bytes(b"VALID NAR")
    (cache / "sample.narinfo").write_bytes(b"NEW SIGNED METADATA\n")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    rsync = bindir / "rsync"
    rsync.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$RSYNC_ARGS_LOG\"\n"
        "case \" $* \" in\n"
        "  *' --include=*.narinfo '*) touch \"$METADATA_UPLOAD_MARKER\" ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    rsync.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "url = args[-1]\n"
        "with open(os.environ['CURL_ARGS_LOG'], 'a') as log:\n"
        "    log.write(url + '\\n')\n"
        "if url.endswith('/nar/sample.nar.xz'):\n"
        "    sys.stdout.buffer.write(b'VALID NAR')\n"
        "elif url.endswith('/sample.narinfo'):\n"
        "    mode = os.environ['REMOTE_MODE']\n"
        "    if '--output' in args:\n"
        "        dst = pathlib.Path(args[args.index('--output') + 1])\n"
        "        if mode == 'http_error':\n"
        "            dst.write_bytes(b'SERVER ERROR')\n"
        "            sys.stdout.write('500')\n"
        "        elif mode in ('missing_then_published', 'missing_after_upload', 'race_other_metadata'):\n"
        "            dst.write_bytes(b'NOT FOUND')\n"
        "            sys.stdout.write('404')\n"
        "        elif mode == 'mismatched':\n"
        "            dst.write_bytes(b'OLD SIGNED METADATA\\n')\n"
        "            sys.stdout.write('200')\n"
        "        else:\n"
        "            dst.write_bytes(b'NEW SIGNED METADATA\\n')\n"
        "            sys.stdout.write('200')\n"
        "    elif mode == 'missing_after_upload':\n"
        "        sys.exit(22)\n"
        "    elif mode == 'race_other_metadata':\n"
        "        sys.stdout.buffer.write(b'FOREIGN SIGNED METADATA\\n')\n"
        "    else:\n"
        "        sys.stdout.buffer.write(b'NEW SIGNED METADATA\\n')\n"
        "else:\n"
        "    sys.exit(41)\n",
        encoding="utf-8",
    )
    curl.chmod(0o700)
    rsync_log = tmp_path / "rsync.log"
    curl_log = tmp_path / "curl.log"
    marker = tmp_path / "metadata-uploaded"
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{os.environ['PATH']}",
        RUNNER_TEMP=str(tmp_path),
        UPLOAD_KEY_B64=base64.b64encode(b"test-only-key").decode("ascii"),
        CI_NIX_CACHE_SSH_HOST="unreachable.example.invalid",
        CI_NIX_CACHE_SSH_HOST_KEY="ssh-ed25519 TEST",
        CI_NIX_CACHE_URL="https://cache.example.invalid/nix-cache",
        RSYNC_ARGS_LOG=str(rsync_log),
        CURL_ARGS_LOG=str(curl_log),
        METADATA_UPLOAD_MARKER=str(marker),
        REMOTE_MODE=remote_mode,
    )
    result = subprocess.run(
        ["bash", "-e", "-c", script], env=env,
        capture_output=True, text=True, timeout=10, check=False,
    )
    calls = curl_log.read_text(encoding="utf-8").splitlines()
    assert "/nar/sample.nar.xz" in "\n".join(calls)
    assert "/sample.narinfo" in "\n".join(calls), (
        "signed metadata must be read from the real consumer endpoint"
    )
    if remote_mode in ("mismatched", "http_error"):
        assert result.returncode != 0, "conflicting or failed metadata lookup must deny"
        assert not marker.exists(), "must deny before metadata upload"
    elif remote_mode in ("missing_after_upload", "race_other_metadata"):
        assert result.returncode != 0, "missing metadata after upload must deny"
        assert marker.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert marker.exists(), "allowed metadata must still use append-only upload"
    assert not (tmp_path / "ci-nix-cache-upload-key").exists()
    assert not (tmp_path / "ci-nix-cache-known-hosts").exists()

def test_full_nix_ci_budget_covers_measured_complete_gates():
    """The 90-minute job 118756701529 was cancelled before ISO/VM/signature gates."""
    workflow = CONSUMER.read_text(encoding="utf-8")
    assert workflow.count("\n  nix:\n") == 1
    detect, nix_job = workflow.split("\n  nix:\n", 1)
    assert "\n    timeout-minutes: 5\n" in detect
    nix_header = nix_job.split("\n    steps:\n", 1)[0]
    # Bounded increase, not disabling any expensive security checks.
    assert "\n    timeout-minutes: 120\n" in nix_header
    steps = [
        "- name: Verify source identity",
        "- name: Evaluate complete flake without building checks",
        "- name: Prove evaluated Heim-PC contracts",
        "- name: Build storage, VM and physical-gate closures",
        "- name: Build live-gate and inventory ISOs",
        "- name: Build no-IP agent-zone closures",
        "- name: Run scoped VM checks",
        "- name: Prove untrusted signatures are rejected by substitution",
    ]
    indices = [nix_job.index(step) for step in steps]
    assert indices == sorted(indices)
    assert "require-sigs = true" in nix_job
    assert "bash scripts/ci/check_nix_cache_signature_rejection.sh" in nix_job


def test_complete_system_closure_requires_separate_default_deny_opt_in():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    job = workflow.split("\njobs:\n  publish:\n", 1)[1]
    assert (
        "PUBLISH_SYSTEM_CLOSURE: "
        + chr(36)
        + "{{ vars.CI_NIX_CACHE_PUBLISH_SYSTEM_CLOSURE_ENABLED }}"
    ) in job
    assert "environment: ci-cache-publisher" in job
    resolve = job.split("- name: Resolve exact heavy derivations from Main graph", 1)[1].split(
        "- name: Create signed append-only cache payload", 1
    )[0]
    assert 'case "$PUBLISH_SYSTEM_CLOSURE" in' in resolve
    assert '""|false)' in resolve
    assert 'true)' in resolve
    assert '*)' in resolve
    assert "refusing system closure publication" in resolve
    strict_system_pattern = "^/nix/store/[0-9a-z]{32}-nixos-system-heim-pc-[A-Za-z0-9._+-]+$"
    assert strict_system_pattern in resolve
    assert ".#packages.x86_64-linux.heim-pc-storage-target-system" in resolve
    assert (
        ".#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel.outPath"
        in resolve
    )
    assert 'test "$system_path" = "$expected_system_path"' in resolve
    assert 'printf \'system_path=%s\\n\' "$system_path" >> "$GITHUB_OUTPUT"' in resolve


def test_complete_system_closure_follows_same_signed_append_only_readback():
    workflow = PUBLISHER.read_text(encoding="utf-8")
    signed = workflow.split("- name: Create signed append-only cache payload", 1)[1].split(
        "- name: Upload cache through restricted publisher key", 1
    )[0]
    readback = workflow.split("- name: Verify public signed-cache readback", 1)[1]
    for step in (signed, readback):
        assert (
            "SYSTEM_PATH: " + chr(36) + "{{ steps.heavy.outputs.system_path }}"
        ) in step
        assert 'case "$PUBLISH_SYSTEM_CLOSURE" in' in step
        assert '""|false)' in step
        assert 'true)' in step
        assert '*)' in step
        assert "^/nix/store/[0-9a-z]{32}-nixos-system-heim-pc-[A-Za-z0-9._+-]+$" in step
    assert 'publication_paths=( "$OLLAMA_PATH" "$LLAMA_CPP_PATH" )' in signed
    assert 'publication_paths+=( "$SYSTEM_PATH" )' in signed
    assert '"${publication_paths[@]}"' in signed
    assert signed.index("derived_public_key=") < signed.index("nix copy ")
    assert 'closure_paths=( "$OLLAMA_PATH" "$LLAMA_CPP_PATH" )' in readback
    assert 'closure_paths+=( "$SYSTEM_PATH" )' in readback
    assert 'nix path-info --recursive "${closure_paths[@]}"' in readback
    assert 'nix store verify --store "file://$readback_cache_dir" --recursive' in readback
    assert 'cmp -s "$expected_closure" "$remote_closure"' in readback
    assert '"${closure_paths[@]}"' in readback
    assert 'fallback = false' in readback
    assert "require-sigs = false" not in workflow


def test_publisher_all_multiline_run_steps_parse_as_bash_without_execution():
    lines = PUBLISHER.read_text(encoding="utf-8").splitlines()
    scripts = []
    for i, line in enumerate(lines):
        if line != "        run: |":
            continue
        body = []
        for part in lines[i + 1:]:
            if part and not part.startswith("          "):
                break
            body.append(part[10:] if part else "")
        scripts.append("\n".join(body) + "\n")
    assert len(scripts) >= 5
    for index, script in enumerate(scripts):
        result = subprocess.run(
            ["bash", "-n"], input=script, capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"publisher step {index} invalid Bash: {result.stderr}"
        )
