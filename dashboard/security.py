"""Service-boundary authorization and response redaction helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from config import PROTECTED_PATHS

API_VERSION = "2.1"
DEFAULT_MAX_REQUEST_BYTES = 1_048_576


def _csv_env(name: str, default: str = "") -> set[str]:
    """Parse a comma-delimited environment variable into normalized values."""
    return {item.strip() for item in os.environ.get(name, default).split(",") if item.strip()}


def trusted_clients() -> set[str]:
    """Return IPs allowed to call the service without a bearer token."""
    return _csv_env("DRIVESCAN_TRUSTED_CLIENTS", "127.0.0.1,::1")


def service_token() -> str:
    """Return the optional internal-service token."""
    return os.environ.get("DRIVESCAN_SERVICE_TOKEN", "").strip()


def max_request_bytes() -> int:
    """Return the bounded HTTP request size."""
    raw = os.environ.get("DRIVESCAN_MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES))
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_REQUEST_BYTES
    return min(max(value, 16_384), 8_388_608)


def authorized_client(client_host: str | None, supplied_token: str | None) -> bool:
    """Authorize a client by exact source IP or constant-time token comparison."""
    host = (client_host or "").strip()
    if host in trusted_clients():
        return True
    expected = service_token()
    supplied = (supplied_token or "").strip()
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def path_fingerprint(path: str) -> str:
    """Create a stable opaque identity for a filesystem path."""
    normalized = os.path.normcase(os.path.normpath(path))
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:20]


def _protected_names() -> set[str]:
    names: set[str] = set()
    for entry in PROTECTED_PATHS:
        value = entry.strip().rstrip("\\/")
        if value and not value.startswith("__"):
            names.add(Path(value).name.casefold())
    names.update({"personal", "private", "secrets", "credentials", "vault"})
    return names


def redact_path(path: str) -> dict[str, Any]:
    """Return an opaque path identity and a non-sensitive display label."""
    raw = str(path or "")
    normalized = os.path.normpath(raw) if raw else ""
    parts = [part for part in Path(normalized).parts if part not in ("\\", "/")]
    protected_names = _protected_names()
    protected = any(part.casefold() in protected_names for part in parts)
    leaf = parts[-1] if parts else "unknown"
    parent = parts[-2] if len(parts) > 1 else ""
    if protected:
        display = f"[protected]/{leaf}"
    elif parent:
        display = f"…/{parent}/{leaf}"
    else:
        display = leaf
    drive = Path(normalized).drive or (parts[0] if parts else "")
    return {
        "path_id": path_fingerprint(raw),
        "display_path": display,
        "drive": drive,
        "protected": protected,
    }


def public_file_record(record: Any) -> dict[str, Any]:
    """Convert a FileRecord/dict into a renderer-safe DTO."""
    data = record.model_dump() if hasattr(record, "model_dump") else dict(record)
    path_info = redact_path(str(data.get("path") or ""))
    return {
        "id": data.get("id"),
        "scan_id": data.get("scan_id"),
        "path_id": path_info["path_id"],
        "display_path": path_info["display_path"],
        "drive": path_info["drive"],
        "protected": path_info["protected"],
        "filename": data.get("filename"),
        "extension": data.get("extension"),
        "size_bytes": data.get("size_bytes", 0),
        "created_at": data.get("created_at"),
        "modified_at": data.get("modified_at"),
        "accessed_at": data.get("accessed_at"),
        "mime_type": data.get("mime_type"),
        "is_binary": bool(data.get("is_binary")),
    }


def public_source_paths(paths: Iterable[str]) -> list[dict[str, Any]]:
    """Redact a collection of evidence paths."""
    return [redact_path(str(path)) for path in paths]


_QUOTED_WINDOWS_PATH = re.compile(r"(?i)(?P<quote>['\"])(?P<path>[A-Z]:\\[^'\"\r\n]+)(?P=quote)")
_UNQUOTED_WINDOWS_PATH = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s,;:)]+")


def _redact_absolute_paths(text: str) -> str:
    """Replace Windows absolute paths in arbitrary proposal prose."""

    def replace_quoted(match: re.Match[str]) -> str:
        raw_path = match.group("path")
        return f"{match.group('quote')}[path:{path_fingerprint(raw_path)}]{match.group('quote')}"

    def replace_unquoted(match: re.Match[str]) -> str:
        raw_path = match.group(0)
        return f"[path:{path_fingerprint(raw_path)}]"

    text = _QUOTED_WINDOWS_PATH.sub(replace_quoted, text)
    return _UNQUOTED_WINDOWS_PATH.sub(replace_unquoted, text)


def _redact_known_paths(value: Any, replacements: dict[str, str]) -> Any:
    """Recursively replace known and embedded absolute paths in proposal prose."""
    if isinstance(value, str):
        redacted = value
        for raw_path, replacement in replacements.items():
            redacted = redacted.replace(raw_path, replacement)
            redacted = redacted.replace(raw_path.replace("\\", "/"), replacement)
        return _redact_absolute_paths(redacted)
    if isinstance(value, list):
        return [_redact_known_paths(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _redact_known_paths(item, replacements) for key, item in value.items()}
    return value


def public_proposal(proposal: dict[str, Any]) -> dict[str, Any]:
    """Return a proposal without raw paths, source bodies, or embedded path prose."""
    result = dict(proposal)
    sources = [str(path) for path in (result.pop("source_files", []) or [])]
    replacements = {source: f"[path:{path_fingerprint(source)}]" for source in sources if source}
    result = _redact_known_paths(result, replacements)
    result["source_evidence"] = public_source_paths(sources)
    result.pop("existing_functions", None)
    result.pop("existing_classes", None)
    result.pop("duplicate_functions", None)
    result["api_version"] = API_VERSION
    return result
