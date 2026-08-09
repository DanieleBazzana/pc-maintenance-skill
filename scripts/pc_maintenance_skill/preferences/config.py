"""Strict JSON preferences. They can narrow scope, never weaken safety policy."""

import json
from pathlib import Path


class PreferencesError(ValueError):
    pass


_ALLOWED = {"audit_roots", "large_threshold", "max_hash_files"}


def load_preferences(path: Path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise PreferencesError(f"cannot read preferences: {type(exc).__name__}") from exc
    if not isinstance(data, dict) or set(data) - _ALLOWED:
        raise PreferencesError("preferences contain unsupported fields")
    roots = data.get("audit_roots", [])
    if not isinstance(roots, list) or not all(isinstance(root, str) and root for root in roots):
        raise PreferencesError("audit_roots must be a list of absolute paths")
    normalized_roots = [Path(root).expanduser().resolve(strict=False) for root in roots]
    if any(not root.is_absolute() for root in normalized_roots):
        raise PreferencesError("audit_roots must be absolute paths")
    result = {"audit_roots": normalized_roots}
    for key in ("large_threshold", "max_hash_files"):
        value = data.get(key)
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise PreferencesError(f"{key} must be a positive integer")
            result[key] = value
    return result
