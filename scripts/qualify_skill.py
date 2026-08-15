#!/usr/bin/env python3
"""Run strict skill admission and emit a machine-readable receipt."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt import sha256_file, write_receipt  # noqa: E402
from qualification_index import qualification_index_signature  # noqa: E402
from skill_identity import identity_for_skill  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def result(status: str, check_id: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"id": check_id, "status": status, "message": message, **extra}


def exit_code(status: str) -> int:
    return {"passed": 0, "failed": 1, "unavailable": 2, "skipped": 2}[status]


def find_reuse_check(
    index_path: Path | None,
    identity: dict[str, str],
    policy_sha256: str,
    validator_tool: dict[str, str],
    index_key: str | None,
    index_root: Path | None,
) -> dict[str, Any] | None:
    if (
        index_path is None
        or index_key is None
        or len(index_key.encode("utf-8")) < 32
    ):
        return None
    if index_root is not None:
        try:
            if index_path.is_symlink():
                return None
            resolved_index = index_path.resolve(strict=True)
            resolved_root = index_root.resolve(strict=True)
            resolved_index.relative_to(resolved_root)
            index_path = resolved_index
        except (OSError, RuntimeError, ValueError):
            return None
    try:
        payload = load_json(index_path)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        return None

    instruction_match = False
    for record in payload["records"]:
        if not isinstance(record, dict) or record.get("status") != "passed":
            continue
        signature = record.get("signature")
        if (
            not isinstance(signature, str)
            or not hmac.compare_digest(
                signature,
                qualification_index_signature(record, index_key),
            )
        ):
            continue
        record_identity = record.get("identity")
        if not isinstance(record_identity, dict):
            continue
        record_tool = record.get("tool")
        if not isinstance(record_tool, dict) or any(
            record_tool.get(field) != validator_tool.get(field)
            for field in ("name", "version", "commit")
        ):
            continue
        if record_identity.get("instruction_digest") == identity["instruction_digest"]:
            instruction_match = True
        if (
            record.get("policy_sha256") == policy_sha256
            and record_identity.get("package_tree_digest") == identity["package_tree_digest"]
            and record_identity.get("dependency_digest") == identity["dependency_digest"]
            and record_identity.get("source_revision") == identity["source_revision"]
        ):
            return result(
                "passed",
                "qualification-reuse",
                "reused passed qualification for an identical package",
                scope="qualification",
                record_id=record.get("record_id", "unknown"),
            )

    if instruction_match:
        return result(
            "passed",
            "qualification-dedup",
            "instruction identity matched; package qualification remains required",
            scope="instruction-analysis",
        )
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-dir", required=True, type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "policy/skill-admission.json")
    parser.add_argument("--validator-bin", default="skill-validator")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--qualification-index", type=Path)
    parser.add_argument("--qualification-index-root", type=Path)
    parser.add_argument("--source-revision")
    args = parser.parse_args()

    policy = load_json(args.policy)
    versions = load_json(ROOT / "tools/versions.json")
    expected_version = policy["validator"]["version"]
    skill_input_dir = args.skill_dir
    skill_dir = args.skill_dir.resolve()
    checks: list[dict[str, Any]] = []
    unavailable = False
    validation_payload: dict[str, Any] = {}
    policy_sha256 = sha256_file(args.policy)
    validator_tool = versions["skill_validator"]
    index_key = os.environ.get("QUALIFICATION_INDEX_KEY")
    validator_env = os.environ.copy()
    validator_env.pop("QUALIFICATION_INDEX_KEY", None)

    try:
        identity = identity_for_skill(skill_input_dir, args.source_revision)
    except (OSError, ValueError) as error:
        checks.append(result("failed", "package-identity", str(error)))
        receipt = {
            "schema_version": "qualification-receipt/v1",
            "qualification": "skill-admission",
            "status": "failed",
            "subject": {"type": "skill-package", "id": str(skill_dir)},
            "tool": {
                "name": versions["skill_validator"]["name"],
                "version": versions["skill_validator"]["version"],
                "commit": versions["skill_validator"]["commit"],
            },
            "policy": {"id": policy["policy_id"], "sha256": policy_sha256},
            "checks": checks,
        }
        write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return exit_code("failed")

    version_ok = False
    try:
        version_run = subprocess.run(
            [args.validator_bin, "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=validator_env,
        )
        version_text = (version_run.stdout + version_run.stderr).strip()
        version_ok = version_run.returncode == 0 and re.search(
            rf"(?<![0-9])v?{re.escape(expected_version)}(?![0-9])",
            version_text,
        ) is not None
        checks.append(result(
            "passed" if version_ok else "failed",
            "validator-version",
            version_text or "no version output",
        ))
    except FileNotFoundError:
        checks.append(result(
            "unavailable",
            "validator-version",
            f"executable not found: {args.validator_bin}",
        ))
        unavailable = True

    reuse_check = None
    if not unavailable and version_ok:
        reuse_check = find_reuse_check(
            args.qualification_index,
            identity,
            policy_sha256,
            validator_tool,
            index_key,
            args.qualification_index_root,
        )
        if reuse_check is not None:
            checks.append(reuse_check)

    if not unavailable and (
        reuse_check is None or reuse_check["id"] != "qualification-reuse"
    ):
        command = [args.validator_bin, *policy["validator"]["command"], str(skill_dir)]
        run = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=validator_env,
        )
        try:
            validation_payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            validation_payload = {}
        validation_ok = run.returncode == 0 and validation_payload.get("passed") is True
        checks.append(result(
            "passed" if validation_ok else "failed",
            "strict-validation",
            "skill-validator check --strict",
            exit_code=run.returncode,
        ))

        files = validation_payload.get("token_counts", {}).get("files", [])
        file_tokens = [item.get("tokens") for item in files if isinstance(item, dict) and isinstance(item.get("tokens"), int)]
        thresholds = policy["thresholds"]
        token_ok = bool(file_tokens) and sum(file_tokens) <= thresholds["max_total_tokens"] and max(file_tokens) <= thresholds["max_file_tokens"]
        checks.append(result(
            "passed" if token_ok else "failed",
            "token-threshold",
            "token accounting is present and within policy" if token_ok else "token accounting is missing or exceeds policy",
            total_tokens=sum(file_tokens) if file_tokens else None,
            max_file_tokens=max(file_tokens) if file_tokens else None,
        ))

    try:
        final_identity = identity_for_skill(skill_input_dir, args.source_revision)
    except (OSError, ValueError) as error:
        checks.append(result(
            "failed",
            "package-identity",
            f"skill package changed or became unavailable: {error}",
        ))
    else:
        if final_identity != identity:
            checks.append(result(
                "failed",
                "package-identity",
                "skill package changed during qualification",
            ))

    status = "unavailable" if unavailable else ("passed" if all(check["status"] == "passed" for check in checks) else "failed")
    receipt = {
        "schema_version": "qualification-receipt/v1",
        "qualification": "skill-admission",
        "status": status,
        "subject": {"type": "skill-package", "id": str(skill_dir)},
        "tool": {
            "name": validator_tool["name"],
            "version": validator_tool["version"],
            "commit": validator_tool["commit"],
        },
        "policy": {"id": policy["policy_id"], "sha256": policy_sha256},
        "identity": identity,
        "checks": checks,
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return exit_code(status)


if __name__ == "__main__":
    raise SystemExit(main())
