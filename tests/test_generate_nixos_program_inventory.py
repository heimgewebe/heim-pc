import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import generate_nixos_program_inventory as inv

STAMP = '2026-11-16T12:00:00+00:00'


def fixture_runner(argv):
    if argv == ['nixos-version']:
        return 0, '26.05.20261031.fa13731 (NixOS)'
    if argv[:3] == ['nix', 'profile', 'list']:
        return 0, json.dumps({'version': 3, 'elements': {
            'zsh': {'storePaths': ['/nix/store/private'], 'originalUrl': 'https://token@example.invalid'},
            'git': {}}})
    if argv[0] == 'flatpak':
        return 0, 'org.z.App\tZ App\t2.0\norg.a.App\tA App\t1.2.3\n'
    if argv[:2] == ['podman', 'ps']:
        return 0, ('heimgewebe-readeck\tprivate.invalid/readeck:0.20.1\n'
                   'personal-private\tprivate.invalid/private:1.2\n'
                   'immich-server-1\tregistry.invalid/immich:v2.3.1\n')
    if argv[0] == 'systemctl':
        if argv[1] == '--system':
            return 1, 'disabled\n'
        return 0, 'generated\n'
    return 0, 'tool version 1.2.3\nhttps://private.invalid'


def test_exact_observations_order_and_scopes():
    calls = []

    def runner(argv):
        calls.append(argv)
        return fixture_runner(argv)

    data = inv.collect(runner, lambda: STAMP, desktop_loader=lambda: [])
    assert data['nix_profiles'] == {
        'source': 'nix profile list --json', 'observed_at': STAMP,
        'status': 'ok', 'exit_code': 0, 'items': ['git', 'zsh']}
    assert data['os']['items'] == [{'name': 'NixOS', 'version': '26.05.20261031.fa13731'}]
    assert data['flatpak']['items'] == [
        {'id': 'org.a.App', 'name': 'A App', 'version': '1.2.3'},
        {'id': 'org.z.App', 'name': 'Z App', 'version': '2.0'}]
    assert data['podman']['items'] == [
        {'name': 'heimgewebe-readeck', 'image_version': '0.20.1'},
        {'name': 'immich-server-1', 'image_version': 'v2.3.1'}]
    assert list(data['cli']) == sorted(inv.CLI)
    assert data['units']['user:heimgewebe-readeck.service']['items'] == [
        {'exists': True, 'is_enabled': 'generated'}]
    assert data['units']['system:podman.service']['items'] == [
        {'exists': True, 'is_enabled': 'disabled'}]
    assert ['systemctl', '--user', 'is-enabled', 'heimgewebe-penpot.service'] in calls
    assert all('sudo' not in cmd and 'inspect' not in cmd and 'npx' not in cmd for cmd in calls)
    assert 'private' not in json.dumps(data)
    assert '/nix/store' not in json.dumps(data)


@pytest.mark.parametrize('rc,status', [(127, 'unavailable'), (1, 'error'), (126, 'error')])
def test_failures_never_mean_empty_success(rc, status):
    data = inv.collect(lambda argv: (rc, 'private diagnostics /home/name token'), lambda: STAMP, desktop_loader=lambda: [])
    assert data['podman']['status'] == status
    assert 'items' not in data['podman']
    assert data['nix_profiles']['status'] == status
    assert 'private' not in json.dumps(data)
    assert data['units']['user:heimgewebe-penpot.service']['status'] == status


def test_unit_absence_and_bus_failure_are_distinct():
    def runner(argv):
        if argv[0] == 'systemctl':
            return (4, 'not-found\n') if argv[1] == '--user' else (1, '')
        return fixture_runner(argv)
    data = inv.collect(runner, lambda: STAMP, desktop_loader=lambda: [])
    assert data['units']['user:heimgewebe-immich.service']['items'] == [
        {'exists': False, 'is_enabled': 'not-found'}]
    assert data['units']['system:podman.service']['status'] == 'error'


def test_malformed_sources_fail_explicitly():
    data = inv.collect(lambda argv: (0, 'invalid'), lambda: STAMP, desktop_loader=lambda: [])
    for key in ('nix_profiles', 'flatpak', 'podman'):
        assert data[key]['status'] == 'error'
        assert data[key]['reason'] == 'invalid_output'


@pytest.mark.parametrize('value', [
    'https://token@example.invalid/1.2', '/nix/store/private-1.2',
    '100.101.102.103', 'name@private.invalid', 'a.tailnet.invalid',
])
def test_privacy(value):
    assert inv.safe_name(value) == '[redacted]'
    assert inv.version(value) in {'[redacted]', 'unknown'}


def test_run_missing_timeout_and_no_stderr(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError()
    monkeypatch.setattr(inv.subprocess, 'run', missing)
    assert inv.run(['missing']) == (127, '')

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('cmd', 15, output='private')
    monkeypatch.setattr(inv.subprocess, 'run', timeout)
    assert inv.run(['cmd']) == (126, '')


def test_outputs_exact_and_legacy_preserved(tmp_path):
    legacy = ['software-inventory.md', 'program-inventory-summary.md', 'program-inventory.v1.json']
    for name in legacy:
        (tmp_path / name).write_text('HISTORICAL 2026-07-09\n')
    data = inv.collect(fixture_runner, lambda: STAMP, desktop_loader=lambda: [])
    inv.write_outputs(data, tmp_path)
    assert (tmp_path / 'nixos-program-inventory.v1.json').read_text() == (
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + '\n')
    rendered = (tmp_path / 'nixos-program-inventory.md').read_text()
    assert rendered == inv.render(data)
    assert rendered.startswith('---\nrole: reality\nstatus: report\ntemporal_scope: point_in_time\n')
    assert 'HISTORISCHE Pop!_OS' in rendered
    assert all((tmp_path / name).read_text() == 'HISTORICAL 2026-07-09\n' for name in legacy)


def test_root_collection_rejected(monkeypatch):
    monkeypatch.setattr(inv.os, 'geteuid', lambda: 0)
    with pytest.raises(PermissionError, match='root inventory is excluded'):
        inv.collect(fixture_runner, lambda: STAMP, desktop_loader=lambda: [])


def test_compose_app_names_are_curated_without_registry_or_ports():
    def runner(argv):
        if argv[:2] == ["podman", "ps"]:
            return 0, (
                "heimgewebe-paperless_paperless-web_1\tghcr.io/paperless-ngx/paperless-ngx:3.4.2\n"
                "heimgewebe-penpot_penpot-postgres_1\tdocker.io/postgres:15.4\n"
                "immich_server\tghcr.io/immich-app/immich-server:v3.4.1\n"
                "other_personal_container\tprivate.example/secret-service:1.0\n"
            )
        return fixture_runner(argv)
    items=inv.collect(runner,lambda:STAMP)["podman"]["items"]
    names=[x["name"] for x in items]
    assert names == ["heimgewebe-paperless_paperless-web_1",
                     "heimgewebe-penpot_penpot-postgres_1","immich_server"]
    assert "private.example" not in json.dumps(items)
    assert "1.0" not in json.dumps(items)


def test_visible_system_desktop_apps_ignore_hidden_and_no_display(tmp_path):
    apps=tmp_path/"system-applications"
    apps.mkdir()
    (apps/"org.example.Visible.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Example Tool\nExec=do-not-run\n")
    (apps/"org.example.Hidden.desktop").write_text(
        "[Desktop Entry]\nName=Hidden Tool\nHidden=true\n")
    (apps/"org.example.Settings.desktop").write_text(
        "[Desktop Entry]\nName=Settings Tool\nNoDisplay=true\n")
    got=inv.scan_desktop_apps(apps)
    assert got == [{"id":"org.example.Visible","name":"Example Tool"}]
    data=inv.collect(fixture_runner,lambda:STAMP,desktop_loader=lambda:got)
    assert data["desktop_apps"]["status"]=="ok"
    assert data["desktop_apps"]["items"]==got


def test_missing_system_desktop_root_is_not_reported_as_empty_success(tmp_path):
    data=inv.collect(fixture_runner,lambda:STAMP,
                     desktop_loader=lambda:inv.scan_desktop_apps(tmp_path/"missing"))
    assert data["desktop_apps"]["status"]=="unavailable"
    assert "items" not in data["desktop_apps"]


def test_major_image_tags_and_digest_pins_are_described_without_registry():
    def runner(argv):
        if argv[:2] == ["podman", "ps"]:
            return 0, ("immich_postgres\tghcr.io/immich-app/postgres@sha256:abcd\n"
                       "heimgewebe-penpot_penpot-postgres_1\tdocker.io/postgres:15\n")
        return fixture_runner(argv)
    items=inv.collect(runner,lambda:STAMP,desktop_loader=lambda:[])["podman"]["items"]
    assert items == [
        {"name":"heimgewebe-penpot_penpot-postgres_1","image_version":"15"},
        {"name":"immich_postgres","image_version":"digest-pinned"},
    ]


def fake_closure(root, units=(), links=(), masked=()):
    for scope in ("system", "user"):
        (root / "etc/systemd" / scope).mkdir(parents=True)
    (root / "sw/share/applications").mkdir(parents=True)
    for scope, name in units:
        (root / "etc/systemd" / scope / name).write_text("[Unit]\n")
    for scope, name in masked:
        (root / "etc/systemd" / scope / name).symlink_to("/dev/null")
    for scope, name in links:
        path = root / "etc/systemd" / scope / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to("../" + path.name)
    return root


def test_closure_diff_detects_removal_new_unit_mask_and_activation_link(tmp_path):
    before = fake_closure(tmp_path / "old", units=[("system", "old.service"),
                          ("system", "kept.service"), ("user", "user.timer")],
                          links=[("system", "multi-user.target.wants/kept.service")])
    after = fake_closure(tmp_path / "new", units=[("system", "netdata.service"),
                         ("user", "user.timer")], masked=[("system", "kept.service")],
                         links=[("system", "multi-user.target.wants/netdata.service")])
    diff = inv.compare_closures(before, after, "\x60netdata.service\x60")
    assert diff["changes"]["system_units"] == {
        "added": ["netdata.service"], "removed": ["kept.service", "old.service"]}
    assert diff["changes"]["system_masked"]["added"] == ["kept.service"]
    assert diff["changes"]["system_dependency_links"] == {
        "added": ["multi-user.target.wants/netdata.service"],
        "removed": ["multi-user.target.wants/kept.service"]}
    assert diff["changes"]["user_units"] == {"added": [], "removed": []}
    assert diff["new_units_without_literal_function_map_reference"] == []
    assert inv.compare_closures(before, after, "")[
        "new_units_without_literal_function_map_reference"] == ["netdata.service"]


def test_closure_diff_refuses_missing_scope_and_reports_omissions(tmp_path):
    before = fake_closure(tmp_path / "old")
    after = fake_closure(tmp_path / "new", units=[("user", "personal@instance.service")])
    diff = inv.compare_closures(before, after, "")
    assert diff["skipped_metadata_names"]["candidate"]["user"] == 1
    assert "personal" not in json.dumps(diff)
    (after / "etc/systemd/system").rmdir()
    with pytest.raises(ValueError, match="missing declared system unit"):
        inv.compare_closures(before, after, "")


def test_closure_diff_recognizes_indirect_nixos_mask(tmp_path):
    before = fake_closure(tmp_path / "old", units=[("system", "retired.service")])
    after = fake_closure(tmp_path / "new")
    nested = tmp_path / "masked-unit"
    nested.symlink_to("/dev/null")
    (after / "etc/systemd/system/retired.service").symlink_to(nested)
    diff = inv.compare_closures(before, after, "")
    assert diff["changes"]["system_units"]["removed"] == ["retired.service"]
    assert diff["changes"]["system_masked"]["added"] == ["retired.service"]
