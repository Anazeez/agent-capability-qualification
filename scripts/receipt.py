#!/usr/bin/env python3
"""Small, dependency-free helpers for qualification receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

STATUSES = {"passed", "failed", "skipped", "unavailable"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_receipt(receipt: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return ["receipt must be an object"]
    required = {"schema_version", "qualification", "status", "subject", "tool", "checks"}
    errors.extend(f"missing required field: {key}" for key in sorted(required - receipt.keys()))
    if receipt.get("schema_version") != "qualification-receipt/v1":
        errors.append("schema_version must be qualification-receipt/v1")
    if receipt.get("qualification") not in {"skill-admission", "mcp-conformance"}:
        errors.append("qualification is not supported")
    if receipt.get("status") not in STATUSES:
        errors.append("status is not supported")
    for field in ("subject", "tool"):
        if not isinstance(receipt.get(field), dict):
            errors.append(f"{field} must be an object")
    if isinstance(receipt.get("subject"), dict):
        for key in ("type", "id"):
            if not isinstance(receipt["subject"].get(key), str):
                errors.append(f"subject.{key} must be a string")
    if isinstance(receipt.get("tool"), dict):
        for key in ("name", "version"):
            if not isinstance(receipt["tool"].get(key), str):
                errors.append(f"tool.{key} must be a string")
    checks = receipt.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                errors.append(f"checks[{index}] must be an object")
                continue
            if not isinstance(check.get("id"), str):
                errors.append(f"checks[{index}].id must be a string")
            if check.get("status") not in STATUSES:
                errors.append(f"checks[{index}].status is not supported")
    return errors
