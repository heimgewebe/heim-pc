from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import cache_maintenance


class CacheMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_path = (
            Path(__file__).resolve().parents[1]
            / "config"
            / "cache-policy.v1.json"
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir()
        self.policy = cache_maintenance.load_policy(
            self.policy_path,
            home=self.home,
        )
        self.now = 1_800_000_000

    def process_observation(
        self,
        *,
        references: list[dict[str, object]] | None = None,
        complete: bool = True,
        build_pids: list[int] | None = None,
    ) -> dict[str, object]:
        return {
            "complete": complete,
            "process_count": 1,
            "open_file_descriptors_checked": len(references or []),
            "path_references": references or [],
            "active_docker_build_pids": build_pids or [],
            "errors": [] if complete else ["fixture-incomplete"],
        }

    def empty_classes(self) -> dict[str, dict[str, object]]:
        return {
            class_id: {"candidates": [], "exclusions": []}
            for class_id in self.policy["classes"]
        }

    def make_plan(self, candidate: dict[str, object]) -> dict[str, object]:
        class_id = str(candidate["class_id"])
        stable_key = str(candidate["stable_key"])
        metadata = candidate["metadata"]
        if not isinstance(metadata, dict):
            raise AssertionError("fixture candidate metadata must be a dict")
        if class_id == "filesystem_cache":
            self.policy["classes"][class_id]["targets"] = [
                {
                    "id": metadata["target_id"],
                    "path": str(Path(stable_key).parent),
                    "minimum_unused_seconds": 1,
                }
            ]
        elif class_id == "maintenance_journal":
            self.policy["classes"][class_id]["roots"] = [
                str(Path(stable_key).parent)
            ]
            self.policy["classes"][class_id]["keep_newest_per_root"] = 0
            self.policy["classes"][class_id]["minimum_age_seconds"] = 1
        elif class_id == "grabowski_releases":
            self.policy["classes"][class_id]["root"] = str(
                Path(stable_key).parent
            )
        classes = self.empty_classes()
        classes[class_id]["candidates"] = [candidate]
        plan: dict[str, object] = {
            "schema_version": 1,
            "kind": cache_maintenance.PLAN_KIND,
            "policy_id": self.policy["policy_id"],
            "policy_sha256": self.policy["policy_sha256"],
            "generated_at_unix": self.now,
            "home": str(self.home),
            "process_observation": self.process_observation(),
            "pins": [],
            "classes": classes,
            "summary": {
                "candidate_count": 1,
                "candidate_allocated_bytes": candidate["allocated_bytes"],
                "exclusion_count": 0,
                "docker_volumes_considered": False,
                "automatic_cleanup_authorized": False,
            },
            "safety": self.policy["safety"],
        }
        digest = cache_maintenance._sha256_json(
            cache_maintenance._plan_material(plan)
        )
        plan["plan_id"] = digest
        plan["plan_sha256"] = digest
        return plan

    def old_timestamp(self, *, age_seconds: int = 60 * 24 * 60 * 60) -> float:
        return float(self.now - age_seconds)

    def set_tree_mtime(self, path: Path, timestamp: float) -> None:
        if path.is_dir():
            for child in path.rglob("*"):
                os.utime(child, (timestamp, timestamp), follow_symlinks=False)
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)

    def test_policy_loads_fail_closed(self) -> None:
        self.assertEqual(self.policy["schema_version"], 1)
        self.assertFalse(self.policy["automatic_apply"])
        self.assertFalse(self.policy["safety"]["docker_volumes_authorized"])
        self.assertFalse(self.policy["safety"]["referenced_images_authorized"])
        self.assertFalse(self.policy["classes"]["user_journal"]["apply_authorized"])

    def test_process_observation_uses_bounded_rootbroker_for_path_references(self) -> None:
        cache_root = self.home / ".cache" / "pip"
        cache_root.mkdir(parents=True)
        referenced = cache_root / "active"
        referenced.mkdir()
        broker_observation = {
            "kind": "grabowski_process_reference_observation",
            "schema_version": 1,
            "complete": True,
            "target_uid": os.geteuid(),
            "roots": [str(cache_root)],
            "process_count": 7,
            "open_file_descriptors_checked": 11,
            "path_references": [
                {
                    "pid": 42,
                    "uid": os.geteuid(),
                    "kind": "fd",
                    "root": str(cache_root),
                    "path": str(referenced),
                }
            ],
            "errors": [],
            "observation_sha256": "a" * 64,
        }
        build_scan = {
            "complete": True,
            "process_count": 5,
            "active_docker_build_pids": [],
            "errors": [],
        }

        with patch.object(
            cache_maintenance,
            "_process_reference_roots",
            return_value=[cache_root],
        ), patch.object(
            cache_maintenance,
            "_privileged_process_reference_observation",
            return_value=broker_observation,
        ), patch.object(
            cache_maintenance,
            "_docker_build_process_observation",
            return_value=build_scan,
        ):
            observed = cache_maintenance._process_observation(self.policy)

        self.assertTrue(observed["complete"])
        self.assertEqual(observed["open_file_descriptors_checked"], 11)
        self.assertEqual(
            observed["path_references"],
            [{"pid": 42, "kind": "fd", "path": str(referenced)}],
        )
        self.assertEqual(observed["reference_observation_sha256"], "a" * 64)

    def test_process_observation_keeps_reference_observer_failure_fail_closed(self) -> None:
        cache_root = self.home / ".cache" / "pip"
        cache_root.mkdir(parents=True)
        build_scan = {
            "complete": True,
            "process_count": 5,
            "active_docker_build_pids": [],
            "errors": [],
        }
        with patch.object(
            cache_maintenance,
            "_process_reference_roots",
            return_value=[cache_root],
        ), patch.object(
            cache_maintenance,
            "_privileged_process_reference_observation",
            side_effect=RuntimeError("broker unavailable"),
        ), patch.object(
            cache_maintenance,
            "_docker_build_process_observation",
            return_value=build_scan,
        ):
            observed = cache_maintenance._process_observation(self.policy)

        self.assertFalse(observed["complete"])
        self.assertEqual(observed["path_references"], [])
        self.assertIn(
            "reference-observer:observer-failure:RuntimeError",
            observed["errors"],
        )

    def test_process_observation_keeps_build_scan_failure_fail_closed(self) -> None:
        broker_observation = {
            "complete": True,
            "process_count": 5,
            "open_file_descriptors_checked": 10,
            "path_references": [],
            "errors": [],
            "observation_sha256": "b" * 64,
        }
        build_scan = {
            "complete": False,
            "process_count": 5,
            "active_docker_build_pids": [],
            "errors": ["cmdline-permission:42"],
        }
        with patch.object(
            cache_maintenance,
            "_process_reference_roots",
            return_value=[],
        ), patch.object(
            cache_maintenance,
            "_privileged_process_reference_observation",
            return_value=broker_observation,
        ), patch.object(
            cache_maintenance,
            "_docker_build_process_observation",
            return_value=build_scan,
        ):
            observed = cache_maintenance._process_observation(self.policy)

        self.assertFalse(observed["complete"])
        self.assertIn("build-scan:cmdline-permission:42", observed["errors"])

    def test_process_observation_preserves_active_docker_build_detection(self) -> None:
        broker_observation = {
            "complete": True,
            "process_count": 5,
            "open_file_descriptors_checked": 10,
            "path_references": [],
            "errors": [],
            "observation_sha256": "c" * 64,
        }
        build_scan = {
            "complete": True,
            "process_count": 5,
            "active_docker_build_pids": [99],
            "errors": [],
        }
        with patch.object(
            cache_maintenance,
            "_process_reference_roots",
            return_value=[],
        ), patch.object(
            cache_maintenance,
            "_privileged_process_reference_observation",
            return_value=broker_observation,
        ), patch.object(
            cache_maintenance,
            "_docker_build_process_observation",
            return_value=build_scan,
        ):
            observed = cache_maintenance._process_observation(self.policy)

        self.assertTrue(observed["complete"])
        self.assertEqual(observed["active_docker_build_pids"], [99])

    def test_policy_rejects_docker_volume_authority(self) -> None:
        data = json.loads(self.policy_path.read_text(encoding="utf-8"))
        data["safety"]["docker_volumes_authorized"] = True
        path = self.home / "unsafe-policy.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(
            cache_maintenance.PolicyError,
            "docker_volumes_authorized",
        ):
            cache_maintenance.load_policy(path, home=self.home)

    def test_tree_snapshot_records_internal_symlink_without_following_it(self) -> None:
        root = self.home / "cache"
        root.mkdir()
        victim = self.home / "victim"
        victim.write_text("keep\n", encoding="utf-8")
        (root / "link").symlink_to(victim)

        snapshot = cache_maintenance._tree_snapshot(root, max_entries=10)

        self.assertEqual(snapshot["entry_count"], 2)
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep\n")

    def test_tree_snapshot_rejects_symlink_root(self) -> None:
        victim = self.home / "victim"
        victim.mkdir()
        root = self.home / "cache-link"
        root.symlink_to(victim, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink target"):
            cache_maintenance._tree_snapshot(root, max_entries=10)

    def test_tree_snapshot_obeys_scan_deadline(self) -> None:
        root = self.home / "cache"
        root.mkdir()

        with self.assertRaises(cache_maintenance.ScanDeadlineExceeded):
            cache_maintenance._tree_snapshot(
                root,
                max_entries=10,
                deadline_monotonic=0.0,
            )

    def test_filesystem_cache_selects_only_old_unreferenced_children(self) -> None:
        root = self.home / "cache-root"
        root.mkdir()
        old = root / "old"
        old.mkdir()
        (old / "payload").write_bytes(b"payload")
        recent = root / "recent"
        recent.mkdir()
        self.set_tree_mtime(old, self.old_timestamp())
        self.set_tree_mtime(recent, float(self.now))
        spec = self.policy["classes"]["filesystem_cache"]
        spec["targets"] = [
            {
                "id": "fixture",
                "path": str(root),
                "minimum_unused_seconds": 30 * 24 * 60 * 60,
            }
        ]

        result = cache_maintenance._observe_filesystem_cache(
            self.policy,
            self.home,
            self.now,
            self.process_observation(),
            {},
        )

        self.assertEqual(
            [item["stable_key"] for item in result["candidates"]],
            [str(old)],
        )
        self.assertIn(
            "too-recent",
            {item["reason"] for item in result["exclusions"]},
        )

    def test_filesystem_cache_excludes_active_process_reference(self) -> None:
        root = self.home / "cache-root"
        root.mkdir()
        child = root / "active"
        child.mkdir()
        self.set_tree_mtime(child, self.old_timestamp())
        self.policy["classes"]["filesystem_cache"]["targets"] = [
            {
                "id": "fixture",
                "path": str(root),
                "minimum_unused_seconds": 1,
            }
        ]
        processes = self.process_observation(
            references=[{"pid": 42, "kind": "cwd", "path": str(child)}]
        )

        result = cache_maintenance._observe_filesystem_cache(
            self.policy,
            self.home,
            self.now,
            processes,
            {},
        )

        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["exclusions"][0]["reason"], "active-process-reference")

    def test_incomplete_process_observation_blocks_filesystem_candidate(self) -> None:
        root = self.home / "cache-root"
        root.mkdir()
        child = root / "unknown"
        child.mkdir()
        self.set_tree_mtime(child, self.old_timestamp())
        self.policy["classes"]["filesystem_cache"]["targets"] = [
            {"id": "fixture", "path": str(root), "minimum_unused_seconds": 1}
        ]

        with patch.object(cache_maintenance, "_tree_snapshot") as snapshot:
            result = cache_maintenance._observe_filesystem_cache(
                self.policy,
                self.home,
                self.now,
                self.process_observation(complete=False),
                {},
            )

        snapshot.assert_not_called()
        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            result["exclusions"][0]["reason"],
            "process-observation-incomplete",
        )

    def test_trash_candidate_is_bound_to_payload_and_info_pair(self) -> None:
        root = self.home / ".local/share/Trash"
        files = root / "files"
        info = root / "info"
        files.mkdir(parents=True)
        info.mkdir()
        payload = files / "large.bin"
        payload.write_bytes(b"payload")
        deletion = datetime.fromtimestamp(
            self.now - 60 * 24 * 60 * 60,
            tz=timezone.utc,
        ).replace(tzinfo=None)
        (info / "large.bin.trashinfo").write_text(
            "[Trash Info]\n"
            "Path=/home/alex/example%20file\n"
            f"DeletionDate={deletion.isoformat(timespec='seconds')}\n",
            encoding="utf-8",
        )
        self.policy["classes"]["trash"]["root"] = str(root)

        result = cache_maintenance._observe_trash(
            self.policy,
            self.home,
            self.now,
            self.process_observation(),
            {},
        )

        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["kind"], "trash_pair")
        self.assertEqual(
            {item["path"] for item in candidate["paths"]},
            {str(payload), str(info / "large.bin.trashinfo")},
        )
        self.assertNotIn("/home/alex/example file", json.dumps(candidate))

    def test_releases_keep_active_and_newest_fallback(self) -> None:
        root = self.home / "releases"
        root.mkdir()
        names = ["active", "fallback", "old-a", "old-b"]
        for index, name in enumerate(names):
            release = root / name
            release.mkdir()
            (release / "payload").write_text(name, encoding="utf-8")
            timestamp = self.old_timestamp(age_seconds=(index + 1) * 40 * 24 * 60 * 60)
            self.set_tree_mtime(release, timestamp)
        manifest = self.home / "deployment.json"
        manifest.write_text(
            json.dumps({"release_id": "active"}),
            encoding="utf-8",
        )
        spec = self.policy["classes"]["grabowski_releases"]
        spec["root"] = str(root)
        spec["deployment_manifest"] = str(manifest)
        spec["keep_newest_fallbacks"] = 1
        spec["minimum_age_seconds"] = 1

        result = cache_maintenance._observe_releases(
            self.policy,
            self.home,
            self.now,
            self.process_observation(),
            {},
        )

        self.assertEqual(
            {item["metadata"]["release_id"] for item in result["candidates"]},
            {"old-a", "old-b"},
        )
        protected = {
            Path(item["stable_key"]).name
            for item in result["exclusions"]
            if item["reason"] == "active-or-fallback"
        }
        self.assertEqual(protected, {"active", "fallback"})

    def test_releases_block_when_active_identity_is_unavailable(self) -> None:
        root = self.home / "releases"
        root.mkdir()
        old = root / "old"
        old.mkdir()
        self.set_tree_mtime(old, self.old_timestamp())
        manifest = self.home / "deployment.json"
        manifest.write_text(
            json.dumps({"release_id": "missing"}),
            encoding="utf-8",
        )
        spec = self.policy["classes"]["grabowski_releases"]
        spec["root"] = str(root)
        spec["deployment_manifest"] = str(manifest)
        spec["minimum_age_seconds"] = 1

        result = cache_maintenance._observe_releases(
            self.policy,
            self.home,
            self.now,
            self.process_observation(),
            {},
        )

        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            result["exclusions"][0]["reason"],
            "active-release-identity-unavailable",
        )

    def test_maintenance_journal_retains_newest_and_selects_old_tail(self) -> None:
        root = self.home / "journal"
        root.mkdir()
        for index in range(3):
            path = root / f"{index}.json"
            path.write_text("{}\n", encoding="utf-8")
            timestamp = self.old_timestamp(age_seconds=(index + 1) * 40 * 24 * 60 * 60)
            os.utime(path, (timestamp, timestamp))
        spec = self.policy["classes"]["maintenance_journal"]
        spec["roots"] = [str(root)]
        spec["keep_newest_per_root"] = 1
        spec["minimum_age_seconds"] = 1

        result = cache_maintenance._observe_maintenance_journal(
            self.policy,
            self.home,
            self.now,
            {},
        )

        self.assertEqual(len(result["candidates"]), 2)
        self.assertEqual(
            sum(item["reason"] == "retained-newest" for item in result["exclusions"]),
            1,
        )

    def test_build_cache_excludes_mutable_and_blocks_active_build(self) -> None:
        immutable = {
            "ID": "abcdefgh12345678",
            "Size": "1GB",
            "Reclaimable": True,
            "Mutable": False,
            "Shared": False,
            "Type": "regular",
        }
        mutable = {
            "ID": "mutable123456789",
            "Size": "2GB",
            "Reclaimable": True,
            "Mutable": True,
            "Shared": False,
            "Type": "source.local",
        }

        def runner(_argv: list[str]) -> dict[str, object]:
            return {
                "returncode": 0,
                "stdout": json.dumps(immutable) + "\n" + json.dumps(mutable) + "\n",
                "stderr": "",
            }

        allowed = cache_maintenance._observe_docker_build_cache(
            self.policy,
            runner,
            self.process_observation(),
            {},
        )
        blocked = cache_maintenance._observe_docker_build_cache(
            self.policy,
            runner,
            self.process_observation(build_pids=[99]),
            {},
        )

        self.assertEqual(len(allowed["candidates"]), 1)
        self.assertEqual(
            allowed["candidates"][0]["metadata"]["record_ids"],
            [immutable["ID"]],
        )
        self.assertIn(
            "mutable-build-cache-records",
            {item["reason"] for item in allowed["exclusions"]},
        )
        self.assertEqual(blocked["candidates"], [])
        self.assertIn(
            "active-docker-build",
            {item["reason"] for item in blocked["exclusions"]},
        )

    def test_docker_nanosecond_timestamp_is_normalized(self) -> None:
        self.assertEqual(
            cache_maintenance._parse_created(
                "2026-07-07T17:45:38.593448023+00:00"
            ),
            int(
                datetime.fromisoformat(
                    "2026-07-07T17:45:38.593448+00:00"
                ).timestamp()
            ),
        )

    def test_docker_images_exclude_every_container_reference(self) -> None:
        referenced = "sha256:" + "a" * 64
        removable = "sha256:" + "b" * 64
        created = datetime.fromtimestamp(
            self.now - 90 * 24 * 60 * 60,
            tz=timezone.utc,
        ).isoformat()

        def runner(argv: list[str]) -> dict[str, object]:
            if argv[:4] == ["docker", "container", "ls", "-aq"]:
                return {"returncode": 0, "stdout": "a" * 64 + "\n", "stderr": ""}
            if argv[:4] == ["docker", "container", "inspect", "--format"]:
                return {"returncode": 0, "stdout": referenced + "\n", "stderr": ""}
            if argv[:3] == ["docker", "image", "ls"]:
                rows = [
                    {
                        "ID": referenced,
                        "Repository": "postgres",
                        "Tag": "<none>",
                        "Size": "1GB",
                        "Containers": "1",
                    },
                    {
                        "ID": removable,
                        "Repository": "postgres",
                        "Tag": "<none>",
                        "Size": "2GB",
                        "Containers": "0",
                    },
                ]
                return {
                    "returncode": 0,
                    "stdout": "".join(json.dumps(row) + "\n" for row in rows),
                    "stderr": "",
                }
            if argv[:4] == ["docker", "image", "inspect", "--format"]:
                image_id = argv[-1]
                inspected = {
                    "Id": image_id,
                    "Created": created,
                    "Size": 1_000_000_000 if image_id == referenced else 2_000_000_000,
                    "RepoTags": None,
                    "RepoDigests": None,
                }
                return {
                    "returncode": 0,
                    "stdout": json.dumps(inspected) + "\n",
                    "stderr": "",
                }
            raise AssertionError(argv)

        result = cache_maintenance._observe_docker_images(
            self.policy,
            runner,
            self.now,
            {},
        )

        self.assertEqual(
            [item["metadata"]["image_id"] for item in result["candidates"]],
            [removable],
        )
        self.assertIn(
            referenced,
            {
                item["stable_key"]
                for item in result["exclusions"]
                if item["reason"] == "container-referenced"
            },
        )

    def test_plan_hash_is_deterministic_for_same_observations(self) -> None:
        fixed = {"candidates": [], "exclusions": []}
        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(cache_maintenance, "_load_pins", return_value={}),
            patch.object(cache_maintenance, "_observe_filesystem_cache", return_value=fixed),
            patch.object(cache_maintenance, "_observe_trash", return_value=fixed),
            patch.object(cache_maintenance, "_observe_releases", return_value=fixed),
            patch.object(cache_maintenance, "_observe_maintenance_journal", return_value=fixed),
            patch.object(cache_maintenance, "_observe_docker_build_cache", return_value=fixed),
            patch.object(cache_maintenance, "_observe_docker_images", return_value=fixed),
            patch.object(cache_maintenance, "_observe_user_journal", return_value=fixed),
        ):
            first = cache_maintenance.build_plan(
                self.policy,
                home=self.home,
                now=self.now,
                write=False,
            )
            second = cache_maintenance.build_plan(
                self.policy,
                home=self.home,
                now=self.now,
                write=False,
            )

        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertFalse(first["summary"]["docker_volumes_considered"])
        self.assertFalse(first["summary"]["automatic_cleanup_authorized"])

    def test_plan_hash_binds_observation_time(self) -> None:
        fixed = {"candidates": [], "exclusions": []}
        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(cache_maintenance, "_load_pins", return_value={}),
            patch.object(cache_maintenance, "_observe_filesystem_cache", return_value=fixed),
            patch.object(cache_maintenance, "_observe_trash", return_value=fixed),
            patch.object(cache_maintenance, "_observe_releases", return_value=fixed),
            patch.object(cache_maintenance, "_observe_maintenance_journal", return_value=fixed),
            patch.object(cache_maintenance, "_observe_docker_build_cache", return_value=fixed),
            patch.object(cache_maintenance, "_observe_docker_images", return_value=fixed),
            patch.object(cache_maintenance, "_observe_user_journal", return_value=fixed),
        ):
            first = cache_maintenance.build_plan(
                self.policy, home=self.home, now=self.now, write=False
            )
            second = cache_maintenance.build_plan(
                self.policy, home=self.home, now=self.now + 1, write=False
            )

        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])

    def test_apply_lock_rejects_symlink(self) -> None:
        state_root = Path(self.policy["resolved_state_root"])
        state_root.mkdir(parents=True)
        victim = self.home / "victim"
        victim.write_text("keep", encoding="utf-8")
        (state_root / "apply.lock").symlink_to(victim)

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError,
            "exclusive state lock",
        ):
            cache_maintenance.apply_plan(
                self.policy,
                {},
                expected_plan_sha256="0" * 64,
                confirmation="invalid",
                selected_candidate_ids=["invalid"],
                now=self.now,
            )

        self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_apply_rejects_forged_path_outside_registered_root(self) -> None:
        path = self.home / "forged"
        path.write_text("payload", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "filesystem_cache",
            str(path),
            "filesystem_entry",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={"target_id": "fixture"},
        )
        plan = self.make_plan(candidate)
        allowed = self.home / "allowed-cache"
        allowed.mkdir()
        self.policy["classes"]["filesystem_cache"]["targets"] = [
            {
                "id": "fixture",
                "path": str(allowed),
                "minimum_unused_seconds": 1,
            }
        ]

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError,
            "outside its registered root",
        ):
            cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertTrue(path.exists())

    def test_apply_rejects_plan_home_mismatch(self) -> None:
        path = self.home / "journal.json"
        path.write_text("{}", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )
        plan = self.make_plan(candidate)
        plan["home"] = "/tmp/forged-home"
        digest = cache_maintenance._sha256_json(
            cache_maintenance._plan_material(plan)
        )
        plan["plan_id"] = digest
        plan["plan_sha256"] = digest

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError, "home identity"
        ):
            cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=digest,
                confirmation=f"APPLY:{digest}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertTrue(path.exists())

    def test_apply_requires_exact_plan_hash_and_confirmation(self) -> None:
        path = self.home / "candidate"
        path.write_text("payload", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )
        plan = self.make_plan(candidate)

        with self.assertRaisesRegex(cache_maintenance.ApplyError, "plan SHA"):
            cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256="0" * 64,
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )
        self.assertTrue(path.exists())

        with self.assertRaisesRegex(cache_maintenance.ApplyError, "confirmation"):
            cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation="wrong",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )
        self.assertTrue(path.exists())

    def test_filesystem_apply_records_before_after_and_replays(self) -> None:
        path = self.home / "candidate"
        path.mkdir()
        (path / "payload").write_bytes(b"payload")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=10)
        candidate = cache_maintenance._candidate(
            "filesystem_cache",
            str(path),
            "filesystem_entry",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={"target_id": "fixture"},
        )
        plan = self.make_plan(candidate)
        arguments = {
            "expected_plan_sha256": plan["plan_sha256"],
            "confirmation": f"APPLY:{plan['plan_id']}",
            "selected_candidate_ids": [candidate["candidate_id"]],
            "now": self.now,
        }

        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(cache_maintenance.time, "time", return_value=self.now),
        ):
            applied = cache_maintenance.apply_plan(
                self.policy, plan, **arguments
            )
            replayed = cache_maintenance.apply_plan(
                self.policy, plan, **arguments
            )

        self.assertEqual(applied["state"], "complete")
        self.assertFalse(path.exists())
        self.assertEqual(applied["before_allocated_bytes"], snapshot["allocated_bytes"])
        self.assertEqual(applied["after_allocated_bytes"], 0)
        self.assertEqual(applied["freed_bytes"], snapshot["allocated_bytes"])
        self.assertFalse(applied["docker_volumes_touched"])
        self.assertTrue(replayed["replayed"])
        self.assertEqual(applied["receipt_sha256"], replayed["receipt_sha256"])

    def test_apply_blocks_identity_drift_without_removing_target(self) -> None:
        path = self.home / "candidate.json"
        path.write_text("before", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )
        plan = self.make_plan(candidate)
        path.write_text("after", encoding="utf-8")

        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(cache_maintenance.time, "time", return_value=self.now),
        ):
            result = cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["error"]["class"], "ApplyError")
        self.assertIn("identity drift", result["error"]["message"])
        self.assertTrue(path.exists())
        self.assertEqual(path.read_text(encoding="utf-8"), "after")

    def test_quarantine_replay_completes_after_crash_between_pair_moves(self) -> None:
        first = self.home / "first"
        second = self.home / "second"
        first.write_text("one", encoding="utf-8")
        second.write_text("two", encoding="utf-8")
        snapshots = [
            cache_maintenance._tree_snapshot(first, max_entries=1),
            cache_maintenance._tree_snapshot(second, max_entries=1),
        ]
        candidate = cache_maintenance._candidate(
            "trash",
            str(first),
            "trash_pair",
            snapshots,
            allocated_bytes=sum(item["allocated_bytes"] for item in snapshots),
            metadata={},
        )
        quarantine = self.home / "quarantine"

        with patch.object(
            cache_maintenance,
            "_after_quarantine_move",
            side_effect=SystemExit("simulated crash"),
        ):
            with self.assertRaises(SystemExit):
                cache_maintenance._apply_filesystem_candidate(
                    candidate,
                    self.policy,
                    quarantine,
                    self.process_observation(),
                )

        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        result = cache_maintenance._apply_filesystem_candidate(
            candidate,
            self.policy,
            quarantine,
            self.process_observation(),
        )

        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["recovered_quarantine_paths"], 1)
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        self.assertFalse(quarantine.exists())

    def test_filesystem_apply_rechecks_age_policy(self) -> None:
        root = self.home / "cache-root"
        root.mkdir()
        path = root / "young"
        path.write_text("payload", encoding="utf-8")
        os.utime(path, (self.now, self.now))
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "filesystem_cache",
            str(path),
            "filesystem_entry",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={"target_id": "fixture"},
        )
        plan = self.make_plan(candidate)
        self.policy["classes"]["filesystem_cache"]["targets"][0][
            "minimum_unused_seconds"
        ] = 3600

        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(
                cache_maintenance.time, "time", return_value=self.now
            ),
        ):
            result = cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertEqual(result["state"], "blocked")
        self.assertIn("age policy", result["error"]["message"])
        self.assertTrue(path.exists())

    def test_journal_apply_rechecks_retained_newest(self) -> None:
        root = self.home / "journal-root"
        root.mkdir()
        path = root / "newest.json"
        path.write_text("{}", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )
        plan = self.make_plan(candidate)
        self.policy["classes"]["maintenance_journal"][
            "keep_newest_per_root"
        ] = 1

        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(
                cache_maintenance.time, "time", return_value=self.now
            ),
        ):
            result = cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertEqual(result["state"], "blocked")
        self.assertIn("retained newest", result["error"]["message"])
        self.assertTrue(path.exists())

    def test_filesystem_apply_blocks_incomplete_process_visibility(self) -> None:
        path = self.home / "candidate"
        path.write_text("payload", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError,
            "process observation is incomplete",
        ):
            cache_maintenance._apply_filesystem_candidate(
                candidate,
                self.policy,
                self.home / "quarantine-incomplete",
                self.process_observation(complete=False),
            )

        self.assertTrue(path.exists())

    def test_filesystem_apply_blocks_new_process_reference(self) -> None:
        path = self.home / "candidate"
        path.write_text("payload", encoding="utf-8")
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "maintenance_journal",
            str(path),
            "journal_file",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={},
        )
        processes = self.process_observation(
            references=[
                {"pid": 42, "kind": "fd", "path": str(path)}
            ]
        )

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError,
            "active process references",
        ):
            cache_maintenance._apply_filesystem_candidate(
                candidate,
                self.policy,
                self.home / "quarantine-active",
                processes,
            )

        self.assertTrue(path.exists())

    def test_apply_rechecks_release_alias_pin(self) -> None:
        path = self.home / "release-v1"
        path.mkdir()
        snapshot = cache_maintenance._tree_snapshot(path, max_entries=1)
        candidate = cache_maintenance._candidate(
            "grabowski_releases",
            str(path),
            "release_directory",
            [snapshot],
            allocated_bytes=snapshot["allocated_bytes"],
            metadata={"release_id": "release-v1"},
        )
        plan = self.make_plan(candidate)
        cache_maintenance.update_pin(
            self.policy,
            target="release-v1",
            reason="recovery fallback",
            ttl_hours=24,
            home=self.home,
            now=self.now,
        )

        with self.assertRaisesRegex(cache_maintenance.ApplyError, "pinned"):
            cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now + 1,
            )

        self.assertTrue(path.exists())

    def test_plan_budget_failure_is_an_explicit_exclusion(self) -> None:
        result = cache_maintenance._observe_with_plan_budget(
            "trash",
            time.monotonic() + 60,
            lambda: (_ for _ in ()).throw(
                cache_maintenance.ScanDeadlineExceeded("budget")
            ),
        )

        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            result["exclusions"][0]["reason"],
            "plan-time-budget-exceeded",
        )

    def test_build_cache_blocks_incomplete_process_visibility(self) -> None:
        result = cache_maintenance._observe_docker_build_cache(
            self.policy,
            lambda _argv: {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            },
            self.process_observation(complete=False),
            {},
        )

        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            result["exclusions"][0]["reason"],
            "process-observation-incomplete",
        )

    def test_build_cache_apply_rechecks_complete_process_visibility(self) -> None:
        record_ids = ["expected12345678"]
        spec = self.policy["classes"]["docker_build_cache"]
        stable = (
            f"{spec['builder']}:"
            f"{cache_maintenance._sha256_json(record_ids)}"
        )
        candidate = cache_maintenance._candidate(
            "docker_build_cache",
            stable,
            "docker_build_cache_set",
            [],
            allocated_bytes=100,
            metadata={
                "builder": spec["builder"],
                "filter": cache_maintenance._build_filter(spec),
                "record_ids": record_ids,
                "records_sha256": "a" * 64,
                "reserved_space_bytes": spec["reserved_space_bytes"],
                "max_used_space_bytes": spec["max_used_space_bytes"],
            },
        )
        plan = self.make_plan(candidate)
        with patch.object(
            cache_maintenance,
            "_process_observation",
            return_value=self.process_observation(complete=False),
        ):
            result = cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertEqual(result["state"], "blocked")
        self.assertIn("incomplete", result["error"]["message"])

    def test_build_cache_apply_blocks_candidate_set_drift(self) -> None:
        expected_ids = ["expected12345678"]
        spec = self.policy["classes"]["docker_build_cache"]
        stable = (
            f"{spec['builder']}:"
            f"{cache_maintenance._sha256_json(expected_ids)}"
        )
        candidate = cache_maintenance._candidate(
            "docker_build_cache",
            stable,
            "docker_build_cache_set",
            [],
            allocated_bytes=100,
            metadata={
                "builder": spec["builder"],
                "filter": cache_maintenance._build_filter(spec),
                "record_ids": expected_ids,
                "records_sha256": "a" * 64,
                "reserved_space_bytes": spec["reserved_space_bytes"],
                "max_used_space_bytes": spec["max_used_space_bytes"],
            },
        )
        plan = self.make_plan(candidate)
        with (
            patch.object(
                cache_maintenance,
                "_process_observation",
                return_value=self.process_observation(),
            ),
            patch.object(
                cache_maintenance,
                "_current_build_candidate",
                return_value=(["foreign12345678"], 100),
            ),
        ):
            result = cache_maintenance.apply_plan(
                self.policy,
                plan,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                selected_candidate_ids=[candidate["candidate_id"]],
                now=self.now,
            )

        self.assertEqual(result["state"], "blocked")
        self.assertIn("candidate set drift", result["error"]["message"])

    def test_release_apply_rechecks_current_active_identity(self) -> None:
        root = self.home / "releases"
        root.mkdir()
        candidate_path = root / "candidate"
        fallback_path = root / "fallback"
        candidate_path.mkdir()
        fallback_path.mkdir()
        manifest = self.home / "deployment.json"
        manifest.write_text(
            json.dumps({"release_id": "candidate"}),
            encoding="utf-8",
        )
        spec = self.policy["classes"]["grabowski_releases"]
        spec["root"] = str(root)
        spec["deployment_manifest"] = str(manifest)
        spec["keep_newest_fallbacks"] = 1
        candidate = cache_maintenance._candidate(
            "grabowski_releases",
            str(candidate_path),
            "release_directory",
            [cache_maintenance._tree_snapshot(candidate_path, max_entries=1)],
            allocated_bytes=0,
            metadata={"release_id": "candidate"},
        )

        with self.assertRaisesRegex(
            cache_maintenance.ApplyError,
            "active or protected fallback",
        ):
            cache_maintenance._require_release_candidate_unprotected(
                candidate, self.policy, self.home
            )

        self.assertTrue(candidate_path.exists())

    def test_container_inventory_is_bounded_and_validated(self) -> None:
        valid = "a" * 64

        def too_many(argv: list[str]) -> dict[str, object]:
            if argv[:4] == ["docker", "container", "ls", "-aq"]:
                return {
                    "returncode": 0,
                    "stdout": valid + "\n" + ("b" * 64) + "\n",
                    "stderr": "",
                }
            raise AssertionError(argv)

        with self.assertRaisesRegex(
            cache_maintenance.PlanError,
            "record limit",
        ):
            cache_maintenance._docker_container_image_ids(
                too_many, max_records=1
            )

        def invalid(argv: list[str]) -> dict[str, object]:
            if argv[:4] == ["docker", "container", "ls", "-aq"]:
                return {
                    "returncode": 0,
                    "stdout": "not-a-container-id\n",
                    "stderr": "",
                }
            raise AssertionError(argv)

        with self.assertRaisesRegex(
            cache_maintenance.PlanError,
            "container id is invalid",
        ):
            cache_maintenance._docker_container_image_ids(
                invalid, max_records=10
            )

    def test_pin_blocks_plan_candidate_and_has_bounded_ttl(self) -> None:
        target = "filesystem_cache:fixture"
        created = cache_maintenance.update_pin(
            self.policy,
            target=target,
            reason="recovery fallback",
            ttl_hours=24,
            home=self.home,
            now=self.now,
        )
        pins = cache_maintenance._load_pins(
            self.policy,
            home=self.home,
            now=self.now + 1,
        )

        self.assertIn(target, pins)
        self.assertEqual(created["expires_at_unix"], self.now + 24 * 3600)
        with self.assertRaisesRegex(ValueError, "between"):
            cache_maintenance.update_pin(
                self.policy,
                target="too-long",
                reason="invalid",
                ttl_hours=self.policy["pins"]["max_ttl_hours"] + 1,
                home=self.home,
                now=self.now,
            )

    def test_user_journal_is_report_only_with_no_candidates(self) -> None:
        result = cache_maintenance._observe_user_journal(
            self.policy,
            lambda _argv: {
                "returncode": 0,
                "stdout": "Archived and active journals take up 1.0G",
                "stderr": "",
            },
        )

        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            result["exclusions"][0]["reason"],
            "report-only-no-exact-target-set",
        )


if __name__ == "__main__":
    unittest.main()
