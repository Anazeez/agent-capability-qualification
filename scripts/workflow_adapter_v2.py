from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


CONTRACT_SHA256 = "0598c73e833d8efb36b0b7ed4a114ef807ae7e8c6af2b05df7405d2e499affaf"
VECTOR_MANIFEST_SHA256 = "66af03e86d67e016d8000902dafd396eb898a6678591fb0291ddc6af846330d3"
VECTOR_TREE_SHA256 = "0c85352c79fca9851777cc8610ec2fface0de45ff4c949fb3bff5182b240ceaa"
TYPED_STATUSES = frozenset(
    {
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
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_manifest",
        "source_identity",
        "dependency_closure",
        "qualification",
    }
)
ADAPTER_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_id",
        "provider_version",
        "source_revision",
        "contract_sha256",
        "vector_tree_sha256",
        "dependency_closure_sha256",
        "status",
        "global_completion_claim",
        "all_required_adapters_passed",
    }
)
SOURCE_FIELDS = frozenset(
    {
        "kind",
        "revision_derivation",
        "source_locator",
        "artifact_sha256",
        "artifact_size",
        "candidate_tree_sha256",
    }
)
DEPENDENCY_FIELDS = frozenset({"required", "available", "lockfiles"})
QUALIFICATION_FIELDS = frozenset(
    {
        "classification",
        "contract_sha256",
        "vector_manifest_sha256",
        "vector_tree_sha256",
        "vector_count",
        "accepted_count",
        "rejected_count",
        "shared_vectors_passed",
        "live_execution_performed",
        "activation_authority",
    }
)


class AdapterQualificationError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def derive_source_revision(source_bytes: bytes, derivation: str) -> str:
    if derivation == "sha1_raw_bytes":
        return hashlib.sha1(source_bytes).hexdigest()
    raise AdapterQualificationError("UNKNOWN_REVISION_DERIVATION")


def preserve_typed_status(status: str) -> str:
    if status not in TYPED_STATUSES:
        raise AdapterQualificationError("UNKNOWN_TYPED_STATUS")
    return status


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def jcode_dispatch_allowed(
    eligibility: Mapping[str, Any],
    dispatch_grant: Mapping[str, Any] | None,
    *,
    now: str,
) -> bool:
    if (
        eligibility.get("adapter_id") != "Jcode"
        or eligibility.get("status") != "PASS"
        or eligibility.get("eligible") is not True
    ):
        return False
    if dispatch_grant is None:
        return False
    current = _parse_datetime(now)
    expires = _parse_datetime(dispatch_grant.get("expires_at"))
    return bool(
        current
        and expires
        and expires > current
        and dispatch_grant.get("schema_version") == "jcode-dispatch-grant/v1"
        and dispatch_grant.get("status") == "ACTIVE"
        and dispatch_grant.get("request_sha256") == eligibility.get("request_sha256")
        and isinstance(dispatch_grant.get("generation"), int)
        and not isinstance(dispatch_grant.get("generation"), bool)
        and dispatch_grant["generation"] > 0
        and dispatch_grant.get("authority") == "Sol"
    )


def _require_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterQualificationError(code)
    return value


def _require_exact_fields(value: Mapping[str, Any], expected: frozenset[str], code: str) -> None:
    if set(value) != expected:
        raise AdapterQualificationError(code)


def _require_sha256(value: Any, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AdapterQualificationError(code)
    return value


def _validate_vector_tree(vector_manifest_path: Path) -> tuple[int, int, int]:
    try:
        manifest_bytes = vector_manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterQualificationError("VECTOR_MANIFEST_UNAVAILABLE") from error
    if hashlib.sha256(manifest_bytes).hexdigest() != VECTOR_MANIFEST_SHA256:
        raise AdapterQualificationError("VECTOR_MANIFEST_SHA256_MISMATCH")
    if manifest.get("schema_version") != "canonical-agent-workflow-vector-manifest/v2":
        raise AdapterQualificationError("VECTOR_MANIFEST_VERSION_MISMATCH")
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or len(vectors) != manifest.get("vector_count"):
        raise AdapterQualificationError("VECTOR_COUNT_MISMATCH")
    seen: set[str] = set()
    for item in vectors:
        if not isinstance(item, dict) or set(item) != {
            "vector_id",
            "file",
            "sha256",
            "expected_decision",
            "expected_reason_code",
        }:
            raise AdapterQualificationError("VECTOR_ENTRY_INVALID")
        vector_id = item["vector_id"]
        if not isinstance(vector_id, str) or not vector_id or vector_id in seen:
            raise AdapterQualificationError("VECTOR_ID_INVALID")
        seen.add(vector_id)
        path = vector_manifest_path.parent / item["file"]
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise AdapterQualificationError("VECTOR_FILE_UNAVAILABLE") from error
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise AdapterQualificationError("VECTOR_FILE_SHA256_MISMATCH")
    accepted = sum(item["expected_decision"] == "ACCEPT" for item in vectors)
    rejected = sum(item["expected_decision"] == "REJECT" for item in vectors)
    if accepted != manifest.get("accepted_count") or rejected != manifest.get("rejected_count"):
        raise AdapterQualificationError("VECTOR_DECISION_COUNT_MISMATCH")
    return len(vectors), accepted, rejected


def qualify_adapter(
    manifest_value: Mapping[str, Any],
    source_path: Path,
    contract_path: Path,
    vector_manifest_path: Path,
) -> dict[str, Any]:
    manifest = _require_object(manifest_value, "MANIFEST_NOT_OBJECT")
    _require_exact_fields(manifest, TOP_LEVEL_FIELDS, "MANIFEST_FIELDS_INVALID")
    if manifest.get("schema_version") != "canonical-workflow-adapter-qualification/v1":
        raise AdapterQualificationError("MANIFEST_VERSION_MISMATCH")

    adapter = _require_object(manifest["adapter_manifest"], "ADAPTER_MANIFEST_NOT_OBJECT")
    source = _require_object(manifest["source_identity"], "SOURCE_IDENTITY_NOT_OBJECT")
    dependencies = _require_object(manifest["dependency_closure"], "DEPENDENCY_CLOSURE_NOT_OBJECT")
    qualification = _require_object(manifest["qualification"], "QUALIFICATION_NOT_OBJECT")
    _require_exact_fields(adapter, ADAPTER_FIELDS, "ADAPTER_MANIFEST_FIELDS_INVALID")
    _require_exact_fields(source, SOURCE_FIELDS, "SOURCE_IDENTITY_FIELDS_INVALID")
    _require_exact_fields(dependencies, DEPENDENCY_FIELDS, "DEPENDENCY_CLOSURE_FIELDS_INVALID")
    _require_exact_fields(qualification, QUALIFICATION_FIELDS, "QUALIFICATION_FIELDS_INVALID")

    try:
        source_bytes = source_path.read_bytes()
        contract_bytes = contract_path.read_bytes()
    except OSError as error:
        raise AdapterQualificationError("REQUIRED_ARTIFACT_UNAVAILABLE") from error
    if hashlib.sha256(source_bytes).hexdigest() != source.get("artifact_sha256"):
        raise AdapterQualificationError("SOURCE_ARTIFACT_SHA256_MISMATCH")
    if len(source_bytes) != source.get("artifact_size"):
        raise AdapterQualificationError("SOURCE_ARTIFACT_SIZE_MISMATCH")
    expected_revision = derive_source_revision(source_bytes, source.get("revision_derivation"))
    if adapter.get("source_revision") != expected_revision or not SHA1_RE.fullmatch(expected_revision):
        raise AdapterQualificationError("SOURCE_REVISION_MISMATCH")
    if source.get("kind") not in {"drive_archive", "session_capability", "qualified_candidate"}:
        raise AdapterQualificationError("SOURCE_KIND_INVALID")
    if not isinstance(source.get("source_locator"), str) or not source["source_locator"]:
        raise AdapterQualificationError("SOURCE_LOCATOR_REQUIRED")
    _require_sha256(source.get("candidate_tree_sha256"), "CANDIDATE_TREE_SHA256_INVALID")

    required = dependencies.get("required")
    available = dependencies.get("available")
    lockfiles = dependencies.get("lockfiles")
    if not isinstance(required, list) or not isinstance(available, list) or not isinstance(lockfiles, list):
        raise AdapterQualificationError("DEPENDENCY_CLOSURE_SHAPE_INVALID")
    if any(not isinstance(item, str) or not item for item in required + available):
        raise AdapterQualificationError("DEPENDENCY_ID_INVALID")
    if len(required) != len(set(required)) or len(available) != len(set(available)):
        raise AdapterQualificationError("DEPENDENCY_ID_DUPLICATE")
    if not set(required) <= set(available):
        raise AdapterQualificationError("DEPENDENCY_CLOSURE_INCOMPLETE")
    for item in lockfiles:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise AdapterQualificationError("LOCKFILE_EVIDENCE_INVALID")
        if not isinstance(item["path"], str) or not item["path"]:
            raise AdapterQualificationError("LOCKFILE_PATH_INVALID")
        _require_sha256(item["sha256"], "LOCKFILE_SHA256_INVALID")
    closure_sha256 = canonical_json_sha256(dependencies)
    if adapter.get("dependency_closure_sha256") != closure_sha256:
        raise AdapterQualificationError("DEPENDENCY_CLOSURE_SHA256_MISMATCH")

    if hashlib.sha256(contract_bytes).hexdigest() != CONTRACT_SHA256:
        raise AdapterQualificationError("CONTRACT_SHA256_MISMATCH")
    vector_count, accepted_count, rejected_count = _validate_vector_tree(vector_manifest_path)
    if adapter.get("schema_version") != "canonical-workflow-adapter-manifest/v1":
        raise AdapterQualificationError("ADAPTER_MANIFEST_VERSION_MISMATCH")
    if not isinstance(adapter.get("adapter_id"), str) or not adapter["adapter_id"]:
        raise AdapterQualificationError("ADAPTER_ID_REQUIRED")
    if not isinstance(adapter.get("provider_version"), str) or not adapter["provider_version"]:
        raise AdapterQualificationError("PROVIDER_VERSION_REQUIRED")
    if adapter.get("contract_sha256") != CONTRACT_SHA256:
        raise AdapterQualificationError("ADAPTER_CONTRACT_SHA256_MISMATCH")
    if adapter.get("vector_tree_sha256") != VECTOR_TREE_SHA256:
        raise AdapterQualificationError("ADAPTER_VECTOR_TREE_SHA256_MISMATCH")
    if adapter.get("status") != "PASS":
        raise AdapterQualificationError("ADAPTER_STATUS_NOT_PASS")
    if adapter.get("global_completion_claim") is not False or adapter.get("all_required_adapters_passed") is not False:
        raise AdapterQualificationError("ADAPTER_GLOBAL_OVERCLAIM")

    expected_qualification = {
        "classification": "PASS_TEST_SHADOW_ONLY",
        "contract_sha256": CONTRACT_SHA256,
        "vector_manifest_sha256": VECTOR_MANIFEST_SHA256,
        "vector_tree_sha256": VECTOR_TREE_SHA256,
        "vector_count": vector_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "shared_vectors_passed": True,
        "live_execution_performed": False,
        "activation_authority": "none",
    }
    if qualification != expected_qualification:
        raise AdapterQualificationError("QUALIFICATION_CLAIM_INVALID")

    return {
        "schema_version": "canonical-workflow-adapter-qualification-result/v1",
        "status": "PASS_TEST_SHADOW_ONLY",
        "adapter_id": adapter["adapter_id"],
        "provider_version": adapter["provider_version"],
        "source_revision": expected_revision,
        "source_artifact_sha256": source["artifact_sha256"],
        "dependency_closure_sha256": closure_sha256,
        "contract_sha256": CONTRACT_SHA256,
        "vector_manifest_sha256": VECTOR_MANIFEST_SHA256,
        "vector_tree_sha256": VECTOR_TREE_SHA256,
        "vectors_passed": vector_count,
        "global_completion_claim": False,
        "activation_authority": "none",
    }
