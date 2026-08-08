#!/usr/bin/env python3
"""Run a client or server against every revision frozen in its profile."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt import write_receipt  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def check(check_id: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"id": check_id, "status": status, "message": message, **extra}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--runner-bin", default="conformance")
    parser.add_argument("--endpoint")
    parser.add_argument("--client-command")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    versions = json.loads((ROOT / "tools/versions.json").read_text(encoding="utf-8"))
    role = profile["role"]
    checks: list[dict[str, Any]] = []
    commands: list[list[str]] = []

    if role not in {"client", "server"}:
        checks.append(check("profile", "failed", f"unsupported role: {role}"))
    elif role == "server" and not args.endpoint and not args.dry_run:
        checks.append(check("profile", "failed", "--endpoint is required for server qualification"))
    elif role == "client" and not args.client_command and not args.dry_run:
        checks.append(check("profile", "failed", "--client-command is required for client qualification"))
    else:
        checks.append(check("profile", "passed", f"valid {role} profile"))

    for revision in profile.get("revisions", []):
        requirements = ROOT / profile["requirements_root"] / f"{revision}.yaml"
        baseline = ROOT / profile["baseline_files"][revision]
        if not requirements.is_file() or not baseline.is_file():
            checks.append(check("manifest:" + revision, "failed", "requirements or baseline file is missing"))
            continue

        command = [args.runner_bin, role]
        if role == "server":
            command += ["--url", args.endpoint or "<endpoint>"]
        else:
            command += ["--command", args.client_command or "<client-command>"]
        command += ["--requirements", revision, "--expected-failures", str(baseline)]
        commands.append(command)

        if args.dry_run:
            checks.append(check("conformance:" + revision, "skipped", "command constructed; runner not invoked", command=command))
            continue

        try:
            run = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            checks.append(check("conformance:" + revision, "unavailable", f"executable not found: {args.runner_bin}", command=command))
            continue
        checks.append(check(
            "conformance:" + revision,
            "passed" if run.returncode == 0 else "failed",
            "revision-frozen conformance command completed",
            command=command,
            exit_code=run.returncode,
        ))

    if any(item["status"] == "failed" for item in checks):
        status = "failed"
    elif any(item["status"] == "unavailable" for item in checks):
        status = "unavailable"
    elif checks and all(item["status"] == "skipped" or item["id"] == "profile" and item["status"] == "passed" for item in checks):
        status = "skipped"
    else:
        status = "passed"

    receipt = {
        "schema_version": "qualification-receipt/v1",
        "qualification": "mcp-conformance",
        "status": status,
        "subject": {"type": "mcp-implementation", "id": profile["profile_id"]},
        "tool": {
            "name": versions["mcp_conformance"]["package"],
            "version": versions["mcp_conformance"]["version"],
            "requirements_anchor": versions["mcp_conformance"]["requirements_anchor"],
        },
        "profile": profile["profile_id"],
        "commands": commands,
        "checks": checks,
    }
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return {"passed": 0, "failed": 1, "unavailable": 2, "skipped": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
