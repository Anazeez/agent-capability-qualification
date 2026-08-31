from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.workflow_adapter_v2 import (
    AdapterQualificationError,
    canonical_json_sha256,
    derive_source_revision,
    jcode_dispatch_allowed,
    preserve_typed_status,
    qualify_adapter,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "canonical-agent-workflow-v2.schema.json"
VECTOR_MANIFEST = ROOT / "fixtures" / "canonical-agent-workflow-v2" / "vector-manifest.json"
CONTRACT_SHA256 = "0598c73e833d8efb36b0b7ed4a114ef807ae7e8c6af2b05df7405d2e499affaf"
VECTOR_MANIFEST_SHA256 = "bbb1f4dd407f8c3881238edb47c3f2b53b420ce964c5fdf4f8a05b656f106614"
VECTOR_TREE_SHA256 = "b3b449c3825e2917e935fafd54fa0d0151c4c933c3238c8dba34dffd1c4ec6ed"


def build_manifest(source: Path) -> dict[str, object]:
    source_bytes = source.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    dependencies = {
        "required": ["python>=3.9", "canonical-agent-workflow/v2"],
        "available": ["canonical-agent-workflow/v2", "python>=3.9"],
        "lockfiles": [],
    }
    closure_sha256 = canonical_json_sha256(dependencies)
    return {
        "schema_version": "canonical-workflow-adapter-qualification/v1",
        "adapter_manifest": {
            "schema_version": "canonical-workflow-adapter-manifest/v1",
            "adapter_id": "Drive",
            "provider_version": "google-drive@0.1.16",
            "source_revision": hashlib.sha1(source_bytes).hexdigest(),
            "contract_sha256": CONTRACT_SHA256,
            "vector_tree_sha256": VECTOR_TREE_SHA256,
            "dependency_closure_sha256": closure_sha256,
            "status": "PASS",
            "global_completion_claim": False,
            "all_required_adapters_passed": False,
        },
        "source_identity": {
            "kind": "drive_archive",
            "revision_derivation": "sha1_raw_bytes",
            "source_locator": "drive-file:1source",
            "artifact_sha256": source_sha256,
            "artifact_size": len(source_bytes),
            "candidate_tree_sha256": source_sha256,
        },
        "dependency_closure": dependencies,
        "qualification": {
            "classification": "PASS_TEST_SHADOW_ONLY",
            "contract_sha256": CONTRACT_SHA256,
            "vector_manifest_sha256": VECTOR_MANIFEST_SHA256,
            "vector_tree_sha256": VECTOR_TREE_SHA256,
            "vector_count": 37,
            "accepted_count": 10,
            "rejected_count": 27,
            "shared_vectors_passed": True,
            "live_execution_performed": False,
            "activation_authority": "none",
        },
    }


class WorkflowAdapterV2Tests(unittest.TestCase):
    def test_valid_shadow_adapter_qualification_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"current source bytes")
            manifest = build_manifest(source)
            result = qualify_adapter(manifest, source, CONTRACT, VECTOR_MANIFEST)
        self.assertEqual(result["status"], "PASS_TEST_SHADOW_ONLY")
        self.assertEqual(result["adapter_id"], "Drive")
        self.assertEqual(result["vectors_passed"], 37)
        self.assertFalse(result["global_completion_claim"])

    def test_source_identity_is_recomputed_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"current source bytes")
            manifest = build_manifest(source)
            source.write_bytes(b"changed source bytes")
            with self.assertRaisesRegex(AdapterQualificationError, "SOURCE_ARTIFACT_SHA256_MISMATCH"):
                qualify_adapter(manifest, source, CONTRACT, VECTOR_MANIFEST)

    def test_vector_tree_digest_binds_the_base_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            source = temporary_root / "source.bin"
            source.write_bytes(b"current source bytes")
            manifest = build_manifest(source)
            fixture_copy = temporary_root / "canonical-agent-workflow-v2"
            shutil.copytree(VECTOR_MANIFEST.parent, fixture_copy)
            base = fixture_copy / "base-valid.json"
            base.write_bytes(base.read_bytes() + b"\n")

            with self.assertRaisesRegex(
                AdapterQualificationError,
                "VECTOR_TREE_SHA256_MISMATCH",
            ):
                qualify_adapter(
                    manifest,
                    source,
                    CONTRACT,
                    fixture_copy / "vector-manifest.json",
                )

    def test_dependency_closure_digest_and_set_equality_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"current source bytes")
            manifest = build_manifest(source)
            manifest["dependency_closure"]["available"] = ["python>=3.9"]
            with self.assertRaisesRegex(AdapterQualificationError, "DEPENDENCY_CLOSURE_INCOMPLETE"):
                qualify_adapter(manifest, source, CONTRACT, VECTOR_MANIFEST)

    def test_local_pass_cannot_claim_global_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"current source bytes")
            manifest = build_manifest(source)
            manifest["adapter_manifest"]["global_completion_claim"] = True
            with self.assertRaisesRegex(AdapterQualificationError, "ADAPTER_GLOBAL_OVERCLAIM"):
                qualify_adapter(manifest, source, CONTRACT, VECTOR_MANIFEST)

    def test_typed_terminal_statuses_are_not_flattened(self) -> None:
        for status in (
            "READY",
            "INLINE",
            "PASS",
            "FAIL_CLOSED",
            "INCOMPLETE",
            "BLOCKED",
            "DENIED",
            "TIMEOUT",
            "ABORTED",
            "CANCELLED",
            "ERROR",
            "UNKNOWN",
        ):
            with self.subTest(status=status):
                self.assertEqual(preserve_typed_status(status), status)
        with self.assertRaisesRegex(AdapterQualificationError, "UNKNOWN_TYPED_STATUS"):
            preserve_typed_status("SUCCESS")

    def test_jcode_qualification_is_never_dispatch_authority(self) -> None:
        eligibility = {
            "adapter_id": "Jcode",
            "status": "PASS",
            "eligible": True,
            "request_sha256": "1" * 64,
        }
        self.assertFalse(jcode_dispatch_allowed(eligibility, None, now="2026-08-31T00:00:00Z"))
        stale_grant = {
            "schema_version": "jcode-dispatch-grant/v1",
            "request_sha256": "2" * 64,
            "generation": 1,
            "expires_at": "2026-08-31T01:00:00Z",
            "status": "ACTIVE",
        }
        self.assertFalse(jcode_dispatch_allowed(eligibility, stale_grant, now="2026-08-31T00:00:00Z"))

    def test_revision_derivation_is_explicit(self) -> None:
        self.assertEqual(
            derive_source_revision(b"source", "sha1_raw_bytes"),
            hashlib.sha1(b"source").hexdigest(),
        )
        with self.assertRaisesRegex(AdapterQualificationError, "UNKNOWN_REVISION_DERIVATION"):
            derive_source_revision(b"source", "first_40_of_sha256")


if __name__ == "__main__":
    unittest.main()
