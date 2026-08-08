#!/usr/bin/env python3
"""Validate a qualification receipt without a third-party JSON-schema package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt import validate_receipt  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("schema", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()

    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"receipt validation failed: {exc}", file=sys.stderr)
        return 1

    if schema.get("properties", {}).get("schema_version", {}).get("const") != "qualification-receipt/v1":
        print("receipt validation failed: schema anchor is incorrect", file=sys.stderr)
        return 1
    errors = validate_receipt(receipt)
    if errors:
        print("receipt validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("receipt validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
