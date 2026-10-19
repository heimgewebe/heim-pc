"""Regression gate for the unchanged full Nix CI coverage under a union build."""

import re
from pathlib import Path

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/heim-pc-nix.yml"
UNION_STEP = "Build all physical, ISO, agent-zone and scoped VM closures"
HEAVY_INSTALLABLES = (
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
BUILD_COMMAND = "nix build --no-link --no-update-lock-file --print-out-paths --print-build-logs"


def test_heavy_installables_share_one_build_with_full_coverage():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert workflow["name"] == "heim-pc-nix"
    assert workflow["jobs"]["nix"]["needs"] == "detect"
    assert workflow["jobs"]["nix"]["timeout-minutes"] == 90
    steps = workflow["jobs"]["nix"]["steps"]
    names = [step["name"] for step in steps]
    assert names.count(UNION_STEP) == 1
    command = steps[names.index(UNION_STEP)]["run"]
    assert command.startswith(BUILD_COMMAND)
    assert command.count("nix build") == 1
    installables = re.findall(r"\.\#(?:nixosConfigurations|packages|checks)\.[^\s]+", command)
    assert len(installables) == len(HEAVY_INSTALLABLES)
    assert tuple(installables) == HEAVY_INSTALLABLES

    for retired_name in (
        "Build storage, VM and physical-gate closures",
        "Build live-gate and inventory ISOs",
        "Build no-IP agent-zone closures",
        "Run scoped VM checks",
    ):
        assert retired_name not in names

    assert names.index("Evaluate complete flake without building checks") < names.index(
        "Prove evaluated Heim-PC contracts"
    ) < names.index("Record heavy-derivation substitution plan") < names.index(
        UNION_STEP
    ) < names.index("Prove untrusted signatures are rejected by substitution")
    assert steps[names.index("Evaluate complete flake without building checks")]["run"].startswith(
        "nix flake check --no-build --no-update-lock-file"
    )
    assert steps[names.index("Prove evaluated Heim-PC contracts")]["run"].startswith(
        BUILD_COMMAND
    )
    assert steps[names.index("Prove untrusted signatures are rejected by substitution")]["run"] == (
        "bash scripts/ci/check_nix_cache_signature_rejection.sh"
    )


def test_union_build_does_not_weaken_cache_or_detection_trust():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "require-sigs = true" in workflow
    assert "fallback = true" in workflow
    assert "extra-trusted-public-keys = heim-pc-ci-cache-20260923-1:" in workflow
    assert "require-sigs = false" not in workflow
    assert "accept-flake-config = true" not in workflow
    assert "if: >-\n      always() &&" in workflow
    assert "needs.detect.outputs.nix_changed != 'false'" in workflow
    assert "EXPECTED_SOURCE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "test \"$(git rev-parse HEAD)\" = \"$EXPECTED_SOURCE_REVISION\"" in workflow
