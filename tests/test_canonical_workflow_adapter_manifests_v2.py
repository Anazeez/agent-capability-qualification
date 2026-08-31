from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from scripts.workflow_adapter_v2 import qualify_adapter
from test_canonical_agent_workflow_v2 import (
    deep_merge,
    evaluate_workflow,
    validate_schema_instance,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "canonical-agent-workflow-v2.schema.json"
FIXTURE_ROOT = ROOT / "fixtures" / "canonical-agent-workflow-v2"
VECTOR_MANIFEST = FIXTURE_ROOT / "vector-manifest.json"
ADAPTER_ROOT = ROOT / "adapters" / "canonical-agent-workflow-v2"
EXTERNAL_SOURCE_ROOT = Path(os.environ.get("CANONICAL_ADAPTER_SOURCE_ROOT", ROOT / ".missing-adapter-sources"))

REQUIRED_ADAPTERS = {
    "chatcut": EXTERNAL_SOURCE_ROOT / "chatcut-current-worktree-2026-08-24.tar.gz",
    "drive": FIXTURE_ROOT / "adapter-sources" / "drive-session-surface-v1.json",
    "jcode": FIXTURE_ROOT / "adapter-sources" / "jcode-eligibility-surface-v1.json",
    "local-mcp": EXTERNAL_SOURCE_ROOT / "local-mcp-source-2026-08-24.zip",
    "luna": FIXTURE_ROOT / "adapter-sources" / "luna-session-surface-v1.json",
    "codex-router": EXTERNAL_SOURCE_ROOT / "codex-router-current-worktree-2026-08-24.tar.gz",
    "reversesum": EXTERNAL_SOURCE_ROOT / "reversesum-current-worktree-2026-08-24.tar.gz",
    "sol-codex": FIXTURE_ROOT / "adapter-sources" / "sol-codex-session-surface-v1.json",
}


class CanonicalWorkflowAdapterManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.vector_manifest = json.loads(VECTOR_MANIFEST.read_text(encoding="utf-8"))
        cls.base = json.loads((FIXTURE_ROOT / cls.vector_manifest["base_file"]).read_text(encoding="utf-8"))

    def test_each_required_adapter_passes_the_identical_shared_vector_tree(self) -> None:
        for slug, source in REQUIRED_ADAPTERS.items():
            with self.subTest(adapter=slug):
                manifest_path = ADAPTER_ROOT / f"{slug}.json"
                self.assertTrue(manifest_path.is_file(), f"missing adapter manifest: {manifest_path}")
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not source.is_absolute():
                    source = ROOT / source
                result = qualify_adapter(manifest, source, CONTRACT, VECTOR_MANIFEST)
                self.assertEqual(result["status"], "PASS_TEST_SHADOW_ONLY")

                adapter_base = dict(self.base)
                adapter_base["adapter_manifest"] = manifest["adapter_manifest"]
                self.assertEqual(validate_schema_instance(adapter_base, self.schema, self.schema), [])
                self.assertEqual(evaluate_workflow(adapter_base), ("ACCEPT", "CONFORMANT"))
                for item in self.vector_manifest["vectors"]:
                    vector = json.loads((FIXTURE_ROOT / item["file"]).read_text(encoding="utf-8"))
                    candidate = deep_merge(adapter_base, vector["overlay"])
                    self.assertEqual(validate_schema_instance(candidate, self.schema, self.schema), [])
                    self.assertEqual(
                        evaluate_workflow(candidate),
                        (item["expected_decision"], item["expected_reason_code"]),
                    )


if __name__ == "__main__":
    unittest.main()
