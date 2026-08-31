from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "canonical-agent-workflow-v2.schema.json"
FIXTURE_ROOT = ROOT / "fixtures" / "canonical-agent-workflow-v2"
MANIFEST_PATH = FIXTURE_ROOT / "vector-manifest.json"

MANDATORY_VECTORS = (
    "current_identity_chain_pass",
    "stale_guidance_hash_fail_closed",
    "stale_receipt_pointer_fail_closed",
    "model_asserted_drive_ready_rejected",
    "material_execute_without_plan_approval_denied",
    "scope_change_invalidates_approval",
    "duplicate_context_hash_deduplicated",
    "equal_authority_context_conflict_blocked",
    "memory_assertion_not_promoted",
    "missing_tool_dependency_hidden",
    "tool_result_over_budget_truncated_with_provenance",
    "control_stage_retry_forbidden",
    "verification_correction_iteration_allowed",
    "fourth_correction_iteration_blocked",
    "confidence_without_evidence_rejected",
    "duplicate_writer_lease_blocked",
    "stale_generation_handoff_blocked",
    "typed_outcomes_not_flattened",
    "unvalidated_candidate_not_published",
    "compare_and_swap_generation_conflict_blocked",
    "docker_canary_without_required_isolation_evidence_rejected",
    "opensandbox_runtime_parity_claim_from_docker_rejected",
    "cleanup_before_readback_denied",
    "adapter_pass_not_global_pass",
)

REQUIRED_DEFINITIONS = {
    "adapter_manifest",
    "authority",
    "capability",
    "context_item",
    "context_projection",
    "control_plane_budget",
    "drive_attestation",
    "evidence_iteration",
    "evidence_loop",
    "plan_approval",
    "provenance",
    "publication_transaction",
    "run_result",
    "sandbox_canary",
    "sha256",
    "workspace_lease",
}


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise AssertionError(f"external reference is not frozen: {ref}")
    value: Any = root
    for token in ref[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    if not isinstance(value, dict):
        raise AssertionError(f"reference is not an object schema: {ref}")
    return value


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise AssertionError(f"unsupported schema type: {expected}")


def validate_schema_instance(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
) -> list[str]:
    if "$ref" in schema:
        return validate_schema_instance(value, resolve_ref(root, schema["$ref"]), root, path)

    errors: list[str] = []
    if "allOf" in schema:
        for child in schema["allOf"]:
            errors.extend(validate_schema_instance(value, child, root, path))
    if "anyOf" in schema:
        if not any(not validate_schema_instance(value, child, root, path) for child in schema["anyOf"]):
            errors.append(f"{path}: no anyOf branch matched")
    if "oneOf" in schema:
        matches = sum(not validate_schema_instance(value, child, root, path) for child in schema["oneOf"])
        if matches != 1:
            errors.append(f"{path}: expected exactly one oneOf match, got {matches}")
    if "not" in schema and not validate_schema_instance(value, schema["not"], root, path):
        errors.append(f"{path}: forbidden schema matched")

    if "if" in schema:
        condition_matches = not validate_schema_instance(value, schema["if"], root, path)
        branch = schema.get("then") if condition_matches else schema.get("else")
        if branch is not None:
            errors.extend(validate_schema_instance(value, branch, root, path))

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is outside enum")

    expected_types = schema.get("type")
    if expected_types is not None:
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if not any(type_matches(value, item) for item in expected_types):
            errors.append(f"{path}: expected type {expected_types}")
            return errors

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property {key}")
        for key, child_value in value.items():
            if key in properties:
                errors.extend(validate_schema_instance(child_value, properties[key], root, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key}")
    elif isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: duplicate array items")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(validate_schema_instance(item, schema["items"], root, f"{path}[{index}]"))
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: string is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: string is too long")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(f"{path}: pattern mismatch")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: invalid date-time")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    return errors


def evaluate_workflow(value: dict[str, Any]) -> tuple[str, str]:
    attestation = value["drive_attestation"]
    if attestation["status"] == "READY" and attestation["asserted_by"] != "validator":
        return "REJECT", "MODEL_ASSERTED_DRIVE_READY"
    if len({
        attestation["guidance_sha256"],
        attestation["manifest_guidance_sha256"],
        attestation["receipt_guidance_sha256"],
    }) != 1:
        return "REJECT", "GUIDANCE_HASH_MISMATCH"
    if (
        attestation["manifest_receipt_file_id"] != attestation["newest_receipt_file_id"]
        or attestation["manifest_receipt_sha256"] != attestation["newest_receipt_sha256"]
    ):
        return "REJECT", "RECEIPT_POINTER_MISMATCH"
    if not (attestation["receipt_in_scope"] and attestation["metadata_readback_verified"] and attestation["content_readback_verified"]):
        return "REJECT", "DRIVE_CHAIN_NOT_READY"

    approval = value["plan_approval"]
    if value["risk_class"] in {"material_mutation", "consequential_external"} and approval["status"] != "APPROVED":
        return "REJECT", "PLAN_APPROVAL_REQUIRED"
    if approval["approved_scope_digest"] != approval["current_scope_digest"]:
        return "REJECT", "APPROVAL_SCOPE_DRIFT"
    identity_pairs = (
        ("approved_request_sha256", "current_request_sha256"),
        ("approved_receipt_sha256", "current_receipt_sha256"),
        ("approved_context_packet_sha256", "current_context_packet_sha256"),
        ("approved_plan_sha256", "current_plan_sha256"),
        ("approved_acceptance_digest", "current_acceptance_digest"),
        ("approved_effects_digest", "current_effects_digest"),
        ("approved_dependency_digest", "current_dependency_digest"),
        ("approved_base_revision_sha256", "current_base_revision_sha256"),
    )
    if any(approval[left] != approval[right] for left, right in identity_pairs):
        return "REJECT", "APPROVAL_IDENTITY_DRIFT"

    projection = value["context_projection"]
    loaded_hashes = [item["sha256"] for item in projection["loaded_items"]]
    if len(loaded_hashes) != len(set(loaded_hashes)):
        return "REJECT", "CONTEXT_DUPLICATE_NOT_DEDUPLICATED"
    if projection["equal_authority_conflict"] and not projection["conflict_blocked"]:
        return "REJECT", "CONTEXT_AUTHORITY_CONFLICT"
    if projection["memory"]["durably_promoted"] and not projection["memory"]["promotion_authorized_by_user"]:
        return "REJECT", "MEMORY_PROMOTION_UNAUTHORIZED"

    for capability in value["capabilities"]:
        closure = set(capability["required_dependencies"]) <= set(capability["available_dependencies"])
        if not closure and (capability["visible"] or capability["executable_now"]):
            return "REJECT", "DEPENDENCY_CLOSURE_MISSING_VISIBLE"
        budget = capability["result_budget"]
        if budget["observed_bytes"] > budget["max_bytes"] and not (
            budget["truncated"] and budget["provenance_preserved"]
        ):
            return "REJECT", "RESULT_BUDGET_UNSAFE"

    control = value["control_plane"]
    if control["retry"] or any(item["attempts"] > 1 for item in control["stages"]):
        return "REJECT", "CONTROL_STAGE_RETRY_FORBIDDEN"

    evidence = value["evidence_loop"]
    if evidence["max_correction_iterations"] > 3 or len(evidence["iterations"]) > 3:
        return "REJECT", "CORRECTION_LIMIT_EXCEEDED"
    if evidence["confidence_only"]:
        return "REJECT", "CONFIDENCE_NOT_EVIDENCE"
    if any(item["plan_sha256"] != approval["current_plan_sha256"] for item in evidence["iterations"]):
        return "REJECT", "CORRECTION_PLAN_DRIFT"

    lease = value["workspace_lease"]
    if lease["live_writer_count"] > 1:
        return "REJECT", "DUPLICATE_WRITER"
    if lease["handoff_generation"] != lease["generation"]:
        return "REJECT", "STALE_HANDOFF_GENERATION"

    result = value["run_result"]
    if result["source_status"] != result["rendered_status"]:
        return "REJECT", "TYPED_OUTCOME_FLATTENED"

    publication = value["publication"]
    if not publication["candidate_validated"] and publication["publication_attempted"]:
        return "REJECT", "UNVALIDATED_PUBLICATION"
    if publication["current_generation"] != publication["expected_generation"] and publication["head_updated"]:
        return "REJECT", "CAS_GENERATION_CONFLICT"
    if not publication["readback_verified"] and publication["cleanup_started"]:
        return "REJECT", "CLEANUP_BEFORE_READBACK"

    canary = value["sandbox_canary"]
    if canary["backend"] != "Docker":
        return "REJECT", "DOCKER_BACKEND_REQUIRED"
    if not all(canary["isolation_evidence"].values()):
        return "REJECT", "DOCKER_ISOLATION_EVIDENCE_MISSING"
    if canary["opensandbox_runtime_parity_claimed"]:
        return "REJECT", "RUNTIME_PARITY_UNPROVEN"

    adapter = value["adapter_manifest"]
    if adapter["status"] == "PASS" and adapter["global_completion_claim"] and not adapter["all_required_adapters_passed"]:
        return "REJECT", "ADAPTER_PASS_OVERCLAIMED"
    return "ACCEPT", "CONFORMANT"


class CanonicalAgentWorkflowV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.base = json.loads((FIXTURE_ROOT / self.manifest["base_file"]).read_text(encoding="utf-8"))

    def test_schema_is_closed_draft_2020_12_contract(self) -> None:
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["$id"], "https://canonical.invalid/contracts/canonical-agent-workflow-v2.schema.json")
        self.assertEqual(self.schema["properties"]["schema_version"]["const"], "canonical-agent-workflow/v2")
        self.assertFalse(self.schema["additionalProperties"])
        self.assertTrue(REQUIRED_DEFINITIONS <= set(self.schema["$defs"]))

    def test_base_record_is_structurally_valid(self) -> None:
        self.assertEqual(validate_schema_instance(self.base, self.schema, self.schema), [])
        self.assertEqual(evaluate_workflow(self.base), ("ACCEPT", "CONFORMANT"))

    def test_manifest_freezes_exact_mandatory_vector_set(self) -> None:
        self.assertEqual(self.manifest["schema_version"], "canonical-agent-workflow-vector-manifest/v2")
        self.assertEqual(tuple(item["vector_id"] for item in self.manifest["vectors"]), MANDATORY_VECTORS)
        self.assertEqual(len({item["vector_id"] for item in self.manifest["vectors"]}), len(MANDATORY_VECTORS))

    def test_vector_files_are_hash_bound_and_conform(self) -> None:
        for item in self.manifest["vectors"]:
            with self.subTest(vector=item["vector_id"]):
                path = FIXTURE_ROOT / item["file"]
                raw = path.read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
                vector = json.loads(raw)
                self.assertEqual(vector["schema_version"], "canonical-agent-workflow-conformance-vector/v2")
                self.assertEqual(vector["vector_id"], item["vector_id"])
                candidate = deep_merge(self.base, vector["overlay"])
                self.assertEqual(validate_schema_instance(candidate, self.schema, self.schema), [])
                self.assertEqual(
                    evaluate_workflow(candidate),
                    (item["expected_decision"], item["expected_reason_code"]),
                )


if __name__ == "__main__":
    unittest.main()
