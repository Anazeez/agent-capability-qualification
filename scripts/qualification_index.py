"""Authenticated qualification-index record helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def qualification_index_signature(record: dict[str, Any], key: str) -> str:
    """Return the HMAC signature for an index record without its signature."""

    unsigned = {name: value for name, value in record.items() if name != "signature"}
    payload = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
