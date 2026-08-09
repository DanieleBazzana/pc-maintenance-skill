import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pc_maintenance_skill.classifier import classify_findings
from pc_maintenance_skill.detectors import detect_all, duplicate_detector, installer_detector, temporary_detector, large_detector
from pc_maintenance_skill.models import (
    Classification, DecisionLayer, Disposition, Finding, PolicyDecision,
    ProtectionSource, ProcessAssessment, ProcessStatus, UserPreferenceDecision,
    apply_user_preference,
)
from pc_maintenance_skill.process_awareness import check_in_use
from pc_maintenance_skill.report import build_report, render_text
from pc_maintenance_skill.safety import evaluate_path
from pc_maintenance_skill.scanner import scan


class FixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "cache").mkdir()
        (self.root / "dev-cache" / "node_modules" / ".cache").mkdir(parents=True)
        (self.root / "project" / ".git").mkdir(parents=True)
        (self.root / "project" / "src").mkdir()
        (self.root / "backup").mkdir()
        (self.root / "logs").mkdir()
        (self.root / "cache" / "browser.cache").write_bytes(b"cache")
        (self.root / "dev-cache" / "node_modules" / ".cache" / "x.bin").write_bytes(b"dev")
        (self.root / "installer.dmg").write_bytes(b"installer")
        (self.root / "logs" / "app.log").write_text("log", encoding="utf-8")
        (self.root / "project" / ".env").write_text("TOKEN=not-read", encoding="utf-8")
        (self.root / "project" / "src" / "main.py").write_text("print('ok')", encoding="utf-8")
        (self.root / "database.sqlite").write_bytes(b"db")
        (self.root / "backup" / "copy.bak").write_bytes(b"backup")
        (self.root / "normal.tmp").write_bytes(b"tmp")
        (self.root / "same-a.bin").write_bytes(b"same")
        (self.root / "same-b.bin").write_bytes(b"same")
        try:
            (self.root / "link-out").symlink_to(Path(tempfile.gettempdir()))
        except OSError:
            self.link_supported = False
        else:
            self.link_supported = True

    def tearDown(self):
        self.tmp.cleanup()


class SafetyTests(FixtureMixin, unittest.TestCase):
    def test_sensitive_and_project_paths_are_protected(self):
        for rel in ("project/.env", "project/.git", "database.sqlite", "backup", "project/src"):
            decision = evaluate_path(self.root / rel, self.root)
            self.assertEqual(decision.classification, Classification.PROTECTED)
        decision = evaluate_path(self.root / "project" / ".env", self.root)
        self.assertEqual(decision.source, ProtectionSource.POLICY)
        self.assertEqual(decision.disposition, Disposition.PROTECTED)

    def test_outside_root_is_protected(self):
        decision = evaluate_path(self.root.parent / "outside", self.root)
        self.assertEqual(decision.classification, Classification.PROTECTED)

    def test_symlink_is_protected(self):
        if not self.link_supported:
            self.skipTest("symlinks unavailable")
        decision = evaluate_path(self.root / "link-out", self.root)
        self.assertEqual(decision.classification, Classification.PROTECTED)

    def test_system_and_external_paths_are_protected(self):
        self.assertEqual(evaluate_path(Path("/System"), self.root).classification, Classification.PROTECTED)
        self.assertEqual(evaluate_path(Path("/Volumes/External"), self.root).classification, Classification.PROTECTED)

    def test_personal_data_root_is_protected_even_when_selected(self):
        documents = self.root / "Documents"
        documents.mkdir()
        candidate = documents / "notes.tmp"
        candidate.write_bytes(b"notes")
        with patch("pc_maintenance_skill.safety.policy.Path.home", return_value=self.root):
            decision = evaluate_path(candidate, documents)
        self.assertEqual(decision.classification, Classification.PROTECTED)


class ClassifierTests(unittest.TestCase):
    def finding(self, classification, process=ProcessStatus.NOT_IN_USE):
        return Finding(path=Path("x"), size=1, mtime=0, category="test", reason="test", evidence="test", policy_classification=classification, process_status=process)

    def test_protected_precedes_review_and_safe(self):
        results = classify_findings([
            self.finding(Classification.SAFE),
            self.finding(Classification.REVIEW),
            self.finding(Classification.PROTECTED),
        ])
        self.assertEqual(results[0].classification, Classification.SAFE)
        self.assertEqual(results[1].classification, Classification.REVIEW)
        self.assertEqual(results[2].classification, Classification.PROTECTED)

    def test_unknown_and_in_use_cannot_be_safe(self):
        for status in (ProcessStatus.UNKNOWN, ProcessStatus.IN_USE):
            f = self.finding(Classification.SAFE, status)
            self.assertEqual(classify_findings([f])[0].classification, Classification.REVIEW)


class ScannerAndDetectorTests(FixtureMixin, unittest.TestCase):
    def test_scanner_is_metadata_only_and_detects_categories(self):
        entries = scan(self.root, allowed_root=self.root)
        findings = detect_all(entries, max_hash_files=1000)
        categories = {f.category for f in findings}
        self.assertTrue({"cache", "developer_cache", "installer", "log", "temporary", "duplicate_candidate"}.issubset(categories))
        env = [f for f in findings if f.path.name == ".env"]
        self.assertTrue(env)
        self.assertTrue(all(f.classification == Classification.PROTECTED for f in env))

    def test_duplicate_hash_limit_is_reported(self):
        entries = scan(self.root, allowed_root=self.root)
        findings = detect_all(entries, max_hash_files=1)
        self.assertTrue(any(f.hash_limit_reached for f in findings))

    def test_sensitive_file_content_is_not_opened_by_scanner(self):
        with patch("pathlib.Path.open", side_effect=AssertionError("content opened")):
            entries = scan(self.root, allowed_root=self.root)
        self.assertTrue(entries)


    def test_installer_context_rejects_library_archives(self):
        cases = [
            self.root / "project" / "node_modules" / "pkg" / "archive.gz",
            self.root / "project" / ".venv" / "lib" / "python3.11" / "site-packages" / "archive.gz",
            self.root / "project" / "node_modules" / "pkg" / "asset.zip",
        ]
        for path in cases:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"archive")
        findings = installer_detector(scan(self.root, allowed_root=self.root))
        self.assertFalse(any(f.path in cases for f in findings))

    def test_installer_context_accepts_downloads_and_keeps_review(self):
        downloads = self.root / "Downloads"
        downloads.mkdir()
        purchased = downloads / "Purchased_Setup.pkg"
        disk_image = downloads / "Tool.dmg"
        archive = downloads / "installer_bundle.zip"
        for path in (purchased, disk_image, archive):
            path.write_bytes(b"installer")
        findings = installer_detector(scan(self.root, allowed_root=self.root))
        paths = {f.path for f in findings}
        self.assertTrue({purchased, disk_image, archive}.issubset(paths))
        self.assertTrue(all(f.classification == Classification.REVIEW for f in findings if f.path in paths))

    def test_node_modules_and_venv_have_context_not_generic_trash(self):
        node = self.root / "project" / "node_modules" / "pkg" / "index.js"
        venv = self.root / "project" / ".venv" / "lib" / "python3.11" / "site-packages" / "module.py"
        node.parent.mkdir(parents=True)
        venv.parent.mkdir(parents=True)
        node.write_text("module", encoding="utf-8")
        venv.write_text("module", encoding="utf-8")
        findings = detect_all(scan(self.root, allowed_root=self.root), max_hash_files=0)
        node_findings = [f for f in findings if f.path == node]
        venv_findings = [f for f in findings if f.path == venv]
        self.assertTrue(any(f.context == "node_modules" for f in node_findings))
        self.assertTrue(any(f.context == "python_venv" for f in venv_findings))
        self.assertTrue(all(f.classification in (Classification.REVIEW, Classification.PROTECTED) for f in node_findings + venv_findings))

    def test_temporary_prefix_alone_is_not_enough(self):
        false_positive = self.root / "tmp.js"
        false_positive.write_text("module", encoding="utf-8")
        real_temp = self.root / "tmp" / "partial.part"
        real_temp.parent.mkdir()
        real_temp.write_bytes(b"partial")
        findings = temporary_detector(scan(self.root, allowed_root=self.root))
        paths = {f.path for f in findings}
        self.assertNotIn(false_positive, paths)
        self.assertIn(real_temp, paths)

    def test_large_finding_includes_context(self):
        path = self.root / "Downloads" / "large-model.bin"
        path.parent.mkdir()
        with path.open("wb") as stream:
            stream.truncate(500 * 1024 * 1024)
        findings = large_detector(scan(self.root, allowed_root=self.root))
        finding = next(f for f in findings if f.path == path)
        self.assertEqual(finding.classification, Classification.REVIEW)
        self.assertIn("location=Downloads", finding.evidence)
        self.assertIn("extension=.bin", finding.evidence)

    def test_same_size_is_not_confirmed_without_hash(self):
        entries = [type("Entry", (), {"path": self.root / f"same-{i}.bin", "size": 4, "mtime": 0, "is_file": True, "is_dir": False, "is_symlink": False, "policy_classification": Classification.REVIEW, "policy_reason": "", "policy_evidence": ""})() for i in range(2)]
        result = duplicate_detector(entries, max_hash_files=0)
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0].sha256)
        self.assertIn("hashing disabled", result[0].reason)

    def test_same_sha256_is_confirmed_candidate(self):
        first = self.root / "hash-a.bin"
        second = self.root / "hash-b.bin"
        first.write_bytes(b"same-content")
        second.write_bytes(b"same-content")
        entries = scan(self.root, allowed_root=self.root)
        result = duplicate_detector([e for e in entries if e.path in (first, second)], max_hash_files=10)
        self.assertTrue(result)
        self.assertTrue(any(f.sha256 for f in result))
        self.assertTrue(all(f.classification == Classification.REVIEW for f in result))


    def test_process_assessment_is_separate_from_finding(self):
        assessment = ProcessAssessment(ProcessStatus.UNKNOWN, source="lsof", reason="timeout")
        self.assertEqual(assessment.status, ProcessStatus.UNKNOWN)


class ModelBoundaryTests(unittest.TestCase):
    def test_user_protection_cannot_override_policy_protection(self):
        policy = PolicyDecision(ProtectionSource.POLICY, Disposition.PROTECTED, "system path", "system")
        user = UserPreferenceDecision(protected=True, reason="keep this")
        merged = apply_user_preference(policy, user)
        self.assertEqual(merged.source, ProtectionSource.POLICY)
        self.assertEqual(merged.disposition, Disposition.PROTECTED)

    def test_user_protection_can_raise_only_unprotected_review(self):
        policy = PolicyDecision(ProtectionSource.NONE, Disposition.REVIEW, "default", "default")
        user = UserPreferenceDecision(protected=True, reason="user choice")
        merged = apply_user_preference(policy, user)
        self.assertEqual(merged.source, ProtectionSource.USER)
        self.assertEqual(merged.disposition, Disposition.PROTECTED)

    def test_finding_keeps_compatibility_and_exposes_decision_boundary(self):
        finding = Finding(Path("x"), 1, 0, "test", "reason", "evidence", Classification.PROTECTED)
        self.assertEqual(finding.decision_layer, DecisionLayer.POLICY_PROTECTED)
        self.assertEqual(finding.classification, Classification.PROTECTED)


class ActionPlanningTests(unittest.TestCase):
    def finding(self, *, category="cache", classification=Classification.SAFE, process=ProcessStatus.NOT_IN_USE, sha256=None):
        return Finding(
            path=Path(f"/audit/{category}.bin"), size=11, mtime=0,
            category=category, reason="test finding", evidence="test",
            policy_classification=classification, classification=classification,
            process_status=process, sha256=sha256,
        )

    def test_safe_cache_is_a_confirmed_quarantine_candidate_only(self):
        from pc_maintenance_skill.actions import EXECUTOR_AVAILABLE, build_action_plan
        plan = build_action_plan(Path("/audit"), [self.finding()], operation_id="plan-1")
        item = plan.items[0]
        self.assertEqual(item.bucket.value, "CLEANUP_CANDIDATE")
        self.assertEqual(item.proposed_action.value, "QUARANTINE")
        self.assertTrue(item.eligible)
        self.assertTrue(item.requires_confirmation)
        self.assertTrue(EXECUTOR_AVAILABLE)
        self.assertEqual(plan.as_dict()["candidate_bytes"], 11)
        self.assertTrue(plan.as_dict()["complete"])
        self.assertTrue(plan.as_dict()["executor_available"])

    def test_active_or_unknown_candidate_is_unavailable(self):
        from pc_maintenance_skill.actions import build_action_plan
        for status in (ProcessStatus.IN_USE, ProcessStatus.UNKNOWN):
            item = build_action_plan(Path("/audit"), [self.finding(process=status)]).items[0]
            self.assertEqual(item.bucket.value, "UNAVAILABLE")
            self.assertEqual(item.proposed_action.value, "NONE")
            self.assertFalse(item.eligible)

    def test_protected_and_duplicate_findings_never_become_automatic_actions(self):
        from pc_maintenance_skill.actions import build_action_plan
        protected = self.finding(category="protected", classification=Classification.PROTECTED)
        duplicate = self.finding(category="duplicate_candidate", classification=Classification.REVIEW, sha256="a" * 64)
        plan = build_action_plan(Path("/audit"), [protected, duplicate])
        by_path = {item.path: item for item in plan.items}
        self.assertEqual(by_path[protected.path].bucket.value, "PROTECTED")
        self.assertEqual(by_path[duplicate.path].bucket.value, "REVIEW_REQUIRED")
        self.assertFalse(by_path[protected.path].eligible)
        self.assertFalse(by_path[duplicate.path].eligible)


class QuarantineTests(FixtureMixin, unittest.TestCase):
    def planned_cache(self, operation_id="quarantine-test"):
        from pc_maintenance_skill.actions import build_action_plan
        cache = self.root / "cache" / "browser.cache"
        entry = next(item for item in scan(self.root, self.root) if item.path == cache)
        finding = Finding(
            cache, entry.size, entry.mtime, "cache", "cache candidate", "cache",
            Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE,
        )
        return cache, build_action_plan(self.root, [finding], operation_id=operation_id, entries=[entry])

    def test_quarantine_and_restore_are_reversible(self):
        from pc_maintenance_skill.actions import execute_quarantine, restore_quarantine
        cache, plan = self.planned_cache()
        quarantine_root = self.root.parent / f"quarantine-{self.root.name}"
        states = {cache: ProcessStatus.NOT_IN_USE, cache.resolve(): ProcessStatus.NOT_IN_USE}
        with patch("pc_maintenance_skill.actions.executor.check_many", return_value=states), \
             patch("pc_maintenance_skill.detectors.coordinator.check_many", return_value=states):
            manifest_path, manifest = execute_quarantine(plan, quarantine_root, "quarantine-test")
        destination = Path(manifest["entries"][0]["destination"])
        self.assertEqual(manifest["state"], "COMPLETED")
        self.assertFalse(cache.exists())
        self.assertTrue(destination.is_file())
        self.assertTrue(manifest_path.is_file())
        restored, restored_manifest = restore_quarantine(manifest_path, "quarantine-test")
        self.assertEqual(restored, 1)
        self.assertEqual(restored_manifest["state"], "RESTORED")
        self.assertTrue(cache.is_file())
        self.assertFalse(destination.exists())

    def test_quarantine_refuses_wrong_confirmation_incomplete_or_changed_plan(self):
        from pc_maintenance_skill.actions import QuarantineError, execute_quarantine
        cache, plan = self.planned_cache("safety-test")
        quarantine_root = self.root.parent / f"quarantine-{self.root.name}"
        with self.assertRaises(QuarantineError):
            execute_quarantine(plan, quarantine_root, "wrong")
        incomplete = type(plan)(plan.operation_id, plan.root, plan.items, {"cache": 1})
        with self.assertRaises(QuarantineError):
            execute_quarantine(incomplete, quarantine_root, "safety-test")
        cache.write_bytes(b"changed")
        with patch("pc_maintenance_skill.actions.executor.check_many", return_value={cache: ProcessStatus.NOT_IN_USE}):
            with self.assertRaises(QuarantineError):
                execute_quarantine(plan, quarantine_root, "safety-test")
        self.assertTrue(cache.exists())

    def test_list_quarantines_reads_manifest_without_mutation(self):
        from pc_maintenance_skill.actions import list_quarantines
        base = self.root / "quarantine-list"
        operation = base / "operation-1"
        operation.mkdir(parents=True)
        manifest = {"operation_id": "operation-1", "state": "COMPLETED", "entries": [{"status": "QUARANTINED"}]}
        (operation / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        before = (operation / "manifest.json").read_bytes()
        result = list_quarantines(base)
        self.assertEqual(result[0]["quarantined"], 1)
        self.assertEqual((operation / "manifest.json").read_bytes(), before)

    def test_purge_requires_mature_preview_token_and_only_deletes_quarantined_fixture(self):
        from pc_maintenance_skill.actions import QuarantineError, preview_purge, purge_quarantine
        operation = self.root / "quarantine-operation"
        files = operation / "files"
        files.mkdir(parents=True)
        target = files / "cache.bin"
        target.write_bytes(b"temporary fixture")
        st = target.stat()
        manifest_path = operation / "manifest.json"
        manifest = {
            "operation_id": "purge-fixture", "quarantine_dir": str(operation),
            "entries": [{"destination": str(target), "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                         "device": st.st_dev, "inode": st.st_ino, "status": "QUARANTINED",
                         "quarantined_at": (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat()}],
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        preview = preview_purge(manifest_path)
        self.assertEqual(preview["entries"][0]["destination"], str(target))
        with self.assertRaises(QuarantineError):
            purge_quarantine(manifest_path, [str(target)], "purge-fixture", "wrong")
        deleted, updated = purge_quarantine(manifest_path, [str(target)], "purge-fixture", preview["entries"][0]["confirmation_token"])
        self.assertEqual(deleted, 1)
        self.assertEqual(updated["state"], "PURGED")
        self.assertFalse(target.exists())

    def test_purge_preview_excludes_entries_younger_than_retention(self):
        from pc_maintenance_skill.actions import preview_purge
        operation = self.root / "young-quarantine"
        files = operation / "files"
        files.mkdir(parents=True)
        target = files / "young.bin"
        target.write_bytes(b"fixture")
        st = target.stat()
        manifest_path = operation / "manifest.json"
        manifest_path.write_text(json.dumps({"operation_id": "young", "quarantine_dir": str(operation), "entries": [{
            "destination": str(target), "size": st.st_size, "mtime_ns": st.st_mtime_ns, "device": st.st_dev,
            "inode": st.st_ino, "status": "QUARANTINED", "quarantined_at": datetime.now(timezone.utc).isoformat(),
        }]}), encoding="utf-8")
        self.assertEqual(preview_purge(manifest_path)["entries"], [])
        self.assertTrue(target.is_file())

    def test_loaded_plan_keeps_fingerprint_and_cli_refuses_missing_confirmation(self):
        from pc_maintenance_skill import cli
        from pc_maintenance_skill.actions import load_action_plan
        _cache, plan = self.planned_cache("load-test")
        report_path = self.root / "plan.json"
        report_path.write_text(json.dumps({"action_plan": plan.as_dict()}), encoding="utf-8")
        loaded = load_action_plan(report_path)
        self.assertEqual(loaded.items[0].expected_inode, plan.items[0].expected_inode)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            cli.main(["quarantine", "--plan-json", str(report_path), "--quarantine-dir", str(self.root.parent / "q")])

    def test_loaded_plan_rejects_changed_integrity_digest(self):
        from pc_maintenance_skill.actions import QuarantineError, load_action_plan
        _cache, plan = self.planned_cache("integrity-test")
        report_path = self.root / "plan.json"
        payload = plan.as_dict()
        payload["items"][0]["size"] += 1
        report_path.write_text(json.dumps({"action_plan": payload}), encoding="utf-8")
        with self.assertRaisesRegex(QuarantineError, "integrity"):
            load_action_plan(report_path)

    def test_executor_refuses_forged_eligible_item_after_independent_scan(self):
        from pc_maintenance_skill.actions import QuarantineError, build_action_plan, execute_quarantine
        from pc_maintenance_skill.models import Finding
        ordinary = self.root / "ordinary.txt"
        ordinary.write_bytes(b"not a cache")
        entry = next(item for item in scan(self.root, self.root) if item.path == ordinary)
        forged_finding = Finding(
            ordinary, entry.size, entry.mtime, "cache", "forged", "forged",
            Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE,
        )
        forged_plan = build_action_plan(self.root, [forged_finding], operation_id="forged-plan", entries=[entry])
        states = {ordinary: ProcessStatus.NOT_IN_USE, ordinary.resolve(): ProcessStatus.NOT_IN_USE}
        with patch("pc_maintenance_skill.actions.executor.check_many", return_value=states), \
             patch("pc_maintenance_skill.detectors.coordinator.check_many", return_value=states):
            with self.assertRaisesRegex(QuarantineError, "independently eligible"):
                execute_quarantine(forged_plan, self.root.parent / "quarantine-forged", "forged-plan")
        self.assertTrue(ordinary.is_file())


class RegistryAndCliBoundaryTests(unittest.TestCase):
    def test_preferences_are_strict_and_can_restrict_audit_roots(self):
        from pc_maintenance_skill.preferences import PreferencesError, load_preferences
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = directory / "preferences.json"
            config.write_text(json.dumps({"audit_roots": [str(directory)], "large_threshold": 123}), encoding="utf-8")
            loaded = load_preferences(config)
            self.assertEqual(loaded["large_threshold"], 123)
            self.assertEqual(loaded["audit_roots"], [directory.resolve()])
            config.write_text(json.dumps({"disable_safety": True}), encoding="utf-8")
            with self.assertRaises(PreferencesError):
                load_preferences(config)

    def test_detector_registry_has_one_entry_per_detector(self):
        from pc_maintenance_skill.detectors.registry import detector_registry
        registry = detector_registry()
        names = [spec.name for spec in registry]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {"cache", "developer_cache", "log", "installer", "temporary", "large", "duplicates"})

    def test_detector_registry_runs_each_detector_once(self):
        from pc_maintenance_skill.detectors.registry import DetectorSpec, run_registered_detectors
        calls = []
        def runner(name):
            def execute(entries, **kwargs):
                calls.append((name, kwargs))
                return []
            return execute
        specs = tuple(DetectorSpec(name, runner(name)) for name in ("cache", "developer_cache", "log", "installer", "temporary", "large", "duplicates"))
        with patch("pc_maintenance_skill.detectors.registry.detector_registry", return_value=specs):
            run_registered_detectors([], max_hash_files=7, large_threshold=123)
        self.assertEqual([name for name, _ in calls], [spec.name for spec in specs])
        self.assertEqual(len(calls), len(specs))

    def test_cli_propagates_large_threshold(self):
        from pc_maintenance_skill import cli
        def fake_scan(root, allowed_root, diagnostics):
            diagnostics["skipped"] = []
            diagnostics["errors"] = []
            return []
        with patch.object(cli, "scan", side_effect=fake_scan), \
             patch.object(cli, "detect_all", return_value=[]) as detector, \
             patch.object(cli, "build_report", return_value=object()), \
             patch.object(cli, "classify_findings", return_value=[]), \
             patch.object(cli, "write_report", return_value=(Path("text"), Path("json"))), \
             patch.object(cli, "append_records"), \
             patch.object(cli, "render_text", return_value="report"):
            # CLI receives diagnostics from the real scanner in normal operation.
            cli.main(["audit", "--root", ".", "--output-dir", "reports", "--large-threshold", "123"])
        self.assertEqual(detector.call_args.kwargs["large_threshold"], 123)

    def test_cli_accepts_plan_mode(self):
        from pc_maintenance_skill import cli
        def fake_scan(root, allowed_root, diagnostics):
            diagnostics["skipped"] = []
            diagnostics["errors"] = []
            return []
        with patch.object(cli, "scan", side_effect=fake_scan), \
             patch.object(cli, "detect_all", return_value=[]), \
             patch.object(cli, "build_report", return_value=object()), \
             patch.object(cli, "classify_findings", return_value=[]), \
             patch.object(cli, "write_report", return_value=(Path("text"), Path("json"))), \
             patch.object(cli, "append_records"), \
             patch.object(cli, "render_text", return_value="report"):
            self.assertEqual(cli.main(["plan", "--root", ".", "--output-dir", "reports"]), 0)

    def test_cli_quarantine_and_restore_require_explicit_operation_inputs(self):
        from pc_maintenance_skill import cli
        from pc_maintenance_skill.actions import build_action_plan
        plan = build_action_plan(Path("/audit"), [], operation_id="cli-plan")
        with patch.object(cli, "load_action_plan", return_value=plan), \
             patch.object(cli, "execute_quarantine", return_value=(Path("manifest.json"), {"state": "COMPLETED"})) as quarantine:
            self.assertEqual(cli.main([
                "quarantine", "--plan-json", "plan.json", "--quarantine-dir", "quarantine", "--confirm-plan", "cli-plan",
            ]), 0)
        self.assertEqual(quarantine.call_args.args[2], "cli-plan")
        with patch.object(cli, "restore_quarantine", return_value=(1, {"state": "RESTORED", "operation_id": "cli-plan"})) as restore:
            self.assertEqual(cli.main([
                "restore", "--manifest", "manifest.json", "--confirm-restore", "cli-plan",
            ]), 0)
        self.assertEqual(restore.call_args.args[1], "cli-plan")


class ProcessTests(unittest.TestCase):
    def test_lsof_unknown_and_not_in_use(self):
        with patch("pc_maintenance_skill.process_awareness.subprocess.run", side_effect=FileNotFoundError):
            self.assertEqual(check_in_use(Path("x")), ProcessStatus.UNKNOWN)
        result = check_in_use(Path("/definitely/not/open"))
        self.assertIn(result, (ProcessStatus.NOT_IN_USE, ProcessStatus.UNKNOWN))


class ReportAndAntiMutationTests(FixtureMixin, unittest.TestCase):
    def snapshot(self):
        result = {}
        for path in sorted(self.root.rglob("*")):
            if path.is_symlink():
                result[str(path.relative_to(self.root))] = ("symlink", os.readlink(path))
            elif path.is_file():
                st = path.stat()
                result[str(path.relative_to(self.root))] = ("file", st.st_mode, st.st_size, path.read_bytes())
            elif path.is_dir():
                result[str(path.relative_to(self.root))] = ("dir", path.stat().st_mode)
        return result

    def test_full_read_only_pipeline_does_not_change_fixture(self):
        before = self.snapshot()
        entries = scan(self.root, allowed_root=self.root)
        findings = classify_findings(detect_all(entries))
        report = build_report(self.root, entries, findings, skipped=[], errors=[], warnings=[])
        text = render_text(report)
        self.assertIn("NO FILESYSTEM CHANGES PERFORMED", text)
        after = self.snapshot()
        self.assertEqual(before, after)

    def test_report_truncates_details_and_preserves_totals(self):
        findings = [Finding(Path(f"/synthetic/cache/{i}.cache"), i + 1, 0, "cache", "cache", "cache", Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE) for i in range(1000)]
        report = build_report(self.root, [], findings, [], [], [])
        data = report.as_dict()
        self.assertEqual(data["category_totals"]["cache"]["count"], 1000)
        self.assertEqual(data["category_totals"]["cache"]["bytes"], sum(range(1, 1001)))
        self.assertEqual(data["truncated_details"]["cache"], 500)
        self.assertLessEqual(len(data["findings"]), 500)

    def test_report_exposes_read_only_action_plan(self):
        from pc_maintenance_skill.actions import build_action_plan
        finding = Finding(Path("/synthetic/cache.cache"), 9, 0, "cache", "cache", "cache", Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE)
        plan = build_action_plan(self.root, [finding], operation_id="plan-report")
        report = build_report(self.root, [], [finding], [], [], [], action_plan=plan)
        data = report.as_dict()
        self.assertEqual(data["action_plan"]["operation_id"], "plan-report")
        self.assertTrue(data["action_plan"]["read_only"])
        self.assertIn("Sorting and action plan", render_text(report))

    def test_action_plan_marks_truncated_details_as_incomplete(self):
        from pc_maintenance_skill.actions import build_action_plan
        finding = Finding(Path("/synthetic/cache.cache"), 9, 0, "cache", "cache", "cache", Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE)
        plan = build_action_plan(self.root, [finding], truncated_categories={"cache": 20})
        self.assertFalse(plan.as_dict()["complete"])
        self.assertEqual(plan.as_dict()["truncated_categories"], {"cache": 20})

    def test_report_handles_100k_findings_without_quadratic_work(self):
        findings = [Finding(Path(f"/synthetic/cache/{i}.cache"), 1, 0, "cache", "cache", "cache", Classification.SAFE, Classification.SAFE, ProcessStatus.NOT_IN_USE) for i in range(100_000)]
        started = __import__("time").perf_counter()
        report = build_report(self.root, [], findings, [], [], [])
        elapsed = __import__("time").perf_counter() - started
        self.assertEqual(report.as_dict()["category_totals"]["cache"]["count"], 100_000)
        self.assertLess(elapsed, 8.0)

    def test_duplicate_findings_are_bounded(self):
        entries = []
        for i in range(2000):
            path = self.root / f"same-{i}.bin"
            path.write_bytes(b"x")
            entries.extend(scan(path.parent, self.root))
            break
        # Use a compact synthetic entry list for the duplicate detector.
        entries = [type("Entry", (), {"path": self.root / f"same-{i}.bin", "size": 1, "mtime": 0, "is_file": True, "is_dir": False, "is_symlink": False, "policy_classification": Classification.REVIEW, "policy_reason": "", "policy_evidence": ""})() for i in range(2000)]
        result = duplicate_detector(entries, max_hash_files=0)
        self.assertLessEqual(len(result), 1)
        self.assertTrue(result[0].hash_limit_reached)

    def test_scanner_entry_reuses_metadata_fields(self):
        entries = scan(self.root, self.root)
        self.assertTrue(entries)
        self.assertTrue(all(hasattr(entry, "name_lower") for entry in entries))
        self.assertTrue(all(hasattr(entry, "suffix_lower") for entry in entries))
        file_entry = next(entry for entry in entries if entry.path.name == "normal.tmp")
        self.assertGreater(file_entry.device, 0)
        self.assertGreater(file_entry.inode, 0)
        self.assertGreater(file_entry.mode, 0)
        self.assertTrue(file_entry.scan_id)
        self.assertEqual(file_entry.metadata_quality, "COMPLETE")
        self.assertIsNotNone(file_entry.policy_decision)

        source_root = Path(__file__).parents[1] / "scripts"
        forbidden = ("os.remove", "os.rename", "os.chmod", "os.chown", "shutil.move", "shutil.rmtree", "subprocess.*sudo")
        for path in source_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, text, msg=f"forbidden API {token} in {path}")
        executor = source_root / "pc_maintenance_skill" / "actions" / "executor.py"
        self.assertIn("os.replace", executor.read_text(encoding="utf-8"))
        for path in source_root.rglob("*.py"):
            if path != executor:
                self.assertNotIn("os.replace", path.read_text(encoding="utf-8"), msg=f"unexpected mutation API in {path}")




class Phase2ArchitectureTests(unittest.TestCase):
    def test_domain_models_are_canonical_and_legacy_models_are_adapters(self):
        from pc_maintenance_skill.domain.models import (
            ActionEligibility, DetectorObservation, Disposition, Finding,
            FileRecord, PolicyDecision, ProcessAssessment, ProtectionSource,
            UserPreferenceDecision,
        )
        from pc_maintenance_skill import models as legacy
        self.assertIs(Finding, legacy.Finding)
        self.assertEqual(ProtectionSource.POLICY.value, "POLICY")
        self.assertEqual(Disposition.PROTECTED.value, "PROTECTED")
        self.assertTrue(all(cls is not None for cls in (
            FileRecord, DetectorObservation, PolicyDecision,
            UserPreferenceDecision, ProcessAssessment, ActionEligibility,
        )))

    def test_phase2_module_boundaries_are_importable(self):
        from pc_maintenance_skill.scanning import scan
        from pc_maintenance_skill.safety import evaluate_path
        from pc_maintenance_skill.duplicates import duplicate_detector
        from pc_maintenance_skill.process import check_many
        from pc_maintenance_skill.classification import classify_findings
        from pc_maintenance_skill.preferences import apply_user_preference
        from pc_maintenance_skill.reporting import build_report
        from pc_maintenance_skill.logging import append_records
        from pc_maintenance_skill.cli import main
        self.assertTrue(all(callable(fn) for fn in (
            scan, evaluate_path, duplicate_detector, check_many,
            classify_findings, apply_user_preference, build_report,
            append_records, main,
        )))

    def test_registry_runners_live_outside_detectors_init(self):
        from pc_maintenance_skill.detectors.registry import detector_registry
        specs = detector_registry()
        self.assertTrue(all(spec.runner.__module__ != "pc_maintenance_skill.detectors" for spec in specs))
        self.assertEqual(len(specs), 7)

    def test_actions_boundary_exposes_only_reversible_executor(self):
        from pc_maintenance_skill.actions import EXECUTOR_AVAILABLE, execute_quarantine, restore_quarantine
        self.assertTrue(EXECUTOR_AVAILABLE)
        self.assertTrue(callable(execute_quarantine))
        self.assertTrue(callable(restore_quarantine))
