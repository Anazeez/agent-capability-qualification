from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.skill_identity import identity_for_skill


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


class QualificationHarnessTests(unittest.TestCase):
    def run_script(self, script: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [PYTHON, str(ROOT / "scripts" / script), *args],
            cwd=ROOT,
            env={**os.environ, **(env or {})},
            text=True,
            capture_output=True,
            check=False,
        )

    def read_receipt(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_skill_identity_digests_are_deterministic_and_package_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "skill"
            (package / "scripts").mkdir(parents=True)
            (package / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
            (package / "scripts/run.sh").write_text("original", encoding="utf-8")
            (package / "package.json").write_text('{"dependencies":{"demo":"1"}}', encoding="utf-8")

            first = identity_for_skill(package, source_revision="source-1")
            second = identity_for_skill(package, source_revision="source-1")
            self.assertEqual(first, second)

            (package / "scripts/run.sh").write_text("changed", encoding="utf-8")
            changed_package = identity_for_skill(package, source_revision="source-1")
            self.assertEqual(first["instruction_digest"], changed_package["instruction_digest"])
            self.assertNotEqual(first["package_tree_digest"], changed_package["package_tree_digest"])

            (package / "package.json").write_text('{"dependencies":{"demo":"2"}}', encoding="utf-8")
            changed_dependency = identity_for_skill(package, source_revision="source-1")
            self.assertNotEqual(changed_package["dependency_digest"], changed_dependency["dependency_digest"])

    def test_skill_identity_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "skill"
            package.mkdir()
            (package / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
            target = Path(temp) / "outside.txt"
            target.write_text("outside", encoding="utf-8")
            (package / "linked.txt").symlink_to(target)

            with self.assertRaises(ValueError):
                identity_for_skill(package, source_revision="source-1")

    def test_skill_qualification_reuses_complete_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            index = Path(temp) / "qualification-index.json"
            skill_dir = ROOT / "fixtures/skills/valid"
            identity = identity_for_skill(skill_dir, source_revision="fixture-source")
            policy_sha256 = hashlib.sha256(
                (ROOT / "policy/skill-admission.json").read_bytes()
            ).hexdigest()
            index.write_text(
                json.dumps({
                    "records": [{
                        "record_id": "prior-valid",
                        "status": "passed",
                        "policy_sha256": policy_sha256,
                        "identity": identity,
                    }]
                }),
                encoding="utf-8",
            )
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(skill_dir),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
                "--qualification-index", str(index),
                "--source-revision", "fixture-source",
                env={"FAKE_VALIDATOR_TOKENS": "5001"},
            )

            self.assertEqual(run.returncode, 0, run.stderr)
            value = self.read_receipt(receipt)
            reuse = next(item for item in value["checks"] if item["id"] == "qualification-reuse")
            self.assertEqual(reuse["status"], "passed")
            self.assertEqual(reuse["scope"], "qualification")

    def test_instruction_match_does_not_skip_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            index = Path(temp) / "qualification-index.json"
            skill_dir = ROOT / "fixtures/skills/valid"
            identity = identity_for_skill(skill_dir, source_revision="fixture-source")
            identity["package_tree_digest"] = "f" * 64
            policy_sha256 = hashlib.sha256(
                (ROOT / "policy/skill-admission.json").read_bytes()
            ).hexdigest()
            index.write_text(
                json.dumps({
                    "records": [{
                        "record_id": "instruction-only",
                        "status": "passed",
                        "policy_sha256": policy_sha256,
                        "identity": identity,
                    }]
                }),
                encoding="utf-8",
            )
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(skill_dir),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
                "--qualification-index", str(index),
                "--source-revision", "fixture-source",
                env={"FAKE_VALIDATOR_TOKENS": "5001"},
            )

            self.assertEqual(run.returncode, 1)
            value = self.read_receipt(receipt)
            dedup = next(item for item in value["checks"] if item["id"] == "qualification-dedup")
            self.assertEqual(dedup["status"], "passed")
            self.assertEqual(dedup["scope"], "instruction-analysis")
            self.assertEqual(next(item for item in value["checks"] if item["id"] == "token-threshold")["status"], "failed")

    def test_malformed_qualification_index_falls_back_to_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            index = Path(temp) / "qualification-index.json"
            index.write_text("not json", encoding="utf-8")
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(ROOT / "fixtures/skills/valid"),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
                "--qualification-index", str(index),
            )

            self.assertEqual(run.returncode, 0, run.stderr)
            value = self.read_receipt(receipt)
            self.assertNotIn("qualification-reuse", {item["id"] for item in value["checks"]})

    def test_skill_qualification_rejects_symlinked_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "skill"
            package.mkdir()
            (package / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
            package_alias = Path(temp) / "skill-alias"
            package_alias.symlink_to(package, target_is_directory=True)
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(package_alias),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
            )

            self.assertEqual(run.returncode, 1)
            value = self.read_receipt(receipt)
            self.assertEqual(value["checks"][0]["id"], "package-identity")

    def test_skill_pass_is_deterministic_and_receipt_validates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(ROOT / "fixtures/skills/valid"),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            value = self.read_receipt(receipt)
            self.assertEqual(value["status"], "passed")
            validation = self.run_script(
                "validate_receipt.py",
                "receipts/schema/qualification-receipt.schema.json",
                str(receipt),
            )
            self.assertEqual(validation.returncode, 0, validation.stderr)

    def test_skill_validator_failure_is_not_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(ROOT / "fixtures/skills/invalid"),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
            )
            self.assertEqual(run.returncode, 1)
            self.assertEqual(self.read_receipt(receipt)["status"], "failed")

    def test_skill_token_threshold_failure_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "skill.json"
            run = self.run_script(
                "qualify_skill.py",
                "--skill-dir", str(ROOT / "fixtures/skills/valid"),
                "--validator-bin", str(ROOT / "fixtures/fake-bin/skill-validator"),
                "--receipt", str(receipt),
                env={"FAKE_VALIDATOR_TOKENS": "5001"},
            )
            self.assertEqual(run.returncode, 1)
            value = self.read_receipt(receipt)
            self.assertEqual(value["status"], "failed")
            self.assertEqual(next(item for item in value["checks"] if item["id"] == "token-threshold")["status"], "failed")

    def test_mcp_dry_run_contains_frozen_revision_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "mcp.json"
            run = self.run_script(
                "qualify_mcp.py",
                "--profile", "mcp/profiles/server.json",
                "--endpoint", "http://127.0.0.1:3000/mcp",
                "--receipt", str(receipt),
                "--dry-run",
            )
            self.assertEqual(run.returncode, 2, run.stderr)
            value = self.read_receipt(receipt)
            self.assertEqual(value["status"], "skipped")
            command_text = " ".join(" ".join(command) for command in value["commands"])
            self.assertIn("--requirements", command_text)
            self.assertIn("2026-07-28", command_text)
            self.assertIn("--expected-failures", command_text)

    def test_mcp_runner_pass_and_fail_are_propagated(self) -> None:
        for expected_exit, expected_status in (("0", "passed"), ("1", "failed")):
            with self.subTest(expected_exit=expected_exit), tempfile.TemporaryDirectory() as temp:
                receipt = Path(temp) / "mcp.json"
                run = self.run_script(
                    "qualify_mcp.py",
                    "--profile", "mcp/profiles/client.json",
                    "--client-command", "python3 fixture-client.py",
                    "--runner-bin", str(ROOT / "fixtures/fake-bin/conformance"),
                    "--receipt", str(receipt),
                    env={"FAKE_CONFORMANCE_EXIT": expected_exit},
                )
                self.assertEqual(run.returncode, 0 if expected_status == "passed" else 1, run.stderr)
                self.assertEqual(self.read_receipt(receipt)["status"], expected_status)

    def test_excluded_surfaces_are_not_scaffolded(self) -> None:
        forbidden = {"registry", "dashboard", "deployment", "telemetry", "governance"}
        top_level = {path.name for path in ROOT.iterdir() if path.is_dir()}
        self.assertTrue(forbidden.isdisjoint(top_level))

    def test_revision_manifest_digests_are_frozen(self) -> None:
        digest_manifest = json.loads((ROOT / "mcp/requirements/manifest-digests.json").read_text(encoding="utf-8"))
        for filename, expected in digest_manifest["sha256"].items():
            actual = hashlib.sha256((ROOT / "mcp/requirements" / filename).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, filename)


if __name__ == "__main__":
    unittest.main()
