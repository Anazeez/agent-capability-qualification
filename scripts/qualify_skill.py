#!/usr/bin/env python3
"""Run strict skill admission and emit a machine-readable receipt."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt import sha256_file, write_receipt  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def result(status: str, check_id: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"id": check_id, "status": status, "message": message, **extra}


def exit_code(status: str) -> int:
    return {"passed": 0, "failed": 1, "unavailable": 2, "skipped": 2}[status]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-dir", required=True, type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "policy/skill-admission.json")
    parser.add_argument("--validator-bin", default="skill-validator")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()

    policy = load_json(args.policy)
    versions = load_json(ROOT / "tools/versions.json")
    expected_version = policy["validator"]["version"]
    skill_dir = args.skill_dir.resolve()
    checks: list[dict[str, Any]] = []
    unavailable = False
    validation_payload: dict[str, Any] = {}

    try:
        version_run = subprocess.run(
            [args.validator_bin, "--version"], capture_output=True, text=True, check=False
        )
        version_text = (version_run.stdout + version_run.stderr).strip()
        version_ok = version_run.returncode == 0 and re.search(rf"(?<![0-9])v?{re.escape(expected_version)}(?![0-9])", version_text)
        checks.append(result("passed" if version_ok else "failed", "validator-version", version_text or "no version output"))
    except FileNotFoundError:
        checks.append(result("unavailable", "validator-version", f"executable not found: {args.validator_bin}"))
        unavailable = True
        version_text = ""

    if not unavailable:
        command = [args.validator_bin, *policy["validator"]["command"], str(skill_dir)]
        run = subprocess.run(command, capture_output=True, text=True, check=False)
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

    status = "unavailable" if unavailable else ("passed" if all(check["status"] == "passed" for check in checks) else "failed")
    receipt = {
        "schema_version": "qualification-receipt/v1",
        "qualification": "skill-admission",
        "status": status,
        "subject": {"type": "skill-package", "id": str(skill_dir)},
        "tool": {
            "name": versions["skill_validator"]["name"],
            "version": versions["skill_validator"]["version"],
            "commit": versions["skill_validator"]["commit"],
        },
        "policy": {"id": policy["policy_id"], "sha256": sha256_file(args.policy)},
        "checks": checks,
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return exit_code(status)


if __name__ == "__main__":
    raise SystemExit(main())
