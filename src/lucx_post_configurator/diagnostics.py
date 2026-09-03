from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any


MAX_DIAGNOSTIC_STRING = 4096
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|token|secret|private_key|pre_shared_key|preshared_key|"
    r"credential(?:s)?|authorization|cookie|api_key|subscription_id|client_id|uuid)(?:$|_)",
    re.IGNORECASE,
)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
CONNECTION_URI_RE = re.compile(
    r"(?i)\b(?:vless|vmess|trojan|ss|shadowsocks|hysteria2?|hy2|naive\+https|"
    r"mierus?|wg|vpn|qwdtt|wdtt|amneziawg)://[^\s]+"
)
HTTP_URI_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
SENSITIVE_QUERY_KEYS = {
    "token",
    "password",
    "passwd",
    "secret",
    "key",
    "api_key",
    "apikey",
    "auth",
}
SENSITIVE_PATH_PREFIXES = {"sub", "awg", "clash", "json"}


def stable_fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _placeholder(label: str, value: Any) -> str:
    try:
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        serialized = str(value)
    return f"<{label}:{stable_fingerprint(serialized)}>"


def _sanitize_http_url(value: str) -> str:
    trailing = ""
    while value and value[-1] in ").,;]}":
        trailing = value[-1] + trailing
        value = value[:-1]
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return _placeholder("redacted-url", value) + trailing
    hostname = parsed.hostname or ""
    if not hostname:
        return _placeholder("redacted-url", value) + trailing
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = host + (f":{port}" if port else "")
    segments = parsed.path.split("/")
    for index, segment in enumerate(segments[:-1]):
        if segment.lower() in SENSITIVE_PATH_PREFIXES and segments[index + 1]:
            segments[index + 1] = _placeholder("id", segments[index + 1])
    query: list[tuple[str, str]] = []
    for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        query.append(
            (key, _placeholder("redacted", item))
            if key.lower() in SENSITIVE_QUERY_KEYS
            else (key, item)
        )
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, "/".join(segments), urllib.parse.urlencode(query), "")
    ) + trailing


def _redact_text(value: str) -> str:
    if len(value) > MAX_DIAGNOSTIC_STRING:
        return _placeholder("redacted-large-value", value)
    value = CONNECTION_URI_RE.sub(
        lambda match: _placeholder("redacted-uri", match.group(0)), value
    )
    value = HTTP_URI_RE.sub(lambda match: _sanitize_http_url(match.group(0)), value)
    value = UUID_RE.sub(lambda match: _placeholder("uuid", match.group(0)), value)
    return value


def _redact_command(value: list[Any]) -> list[Any]:
    result: list[Any] = []
    hide_next = False
    for item in value:
        if hide_next:
            result.append(_placeholder("redacted-argv", item))
            hide_next = False
            continue
        text = str(item)
        flag = text.lstrip("-").replace("-", "_")
        if "=" in flag:
            name, raw = flag.split("=", 1)
            if SENSITIVE_KEY.search(name):
                result.append(text.split("=", 1)[0] + "=" + _placeholder("redacted-argv", raw))
                continue
        if SENSITIVE_KEY.search(flag):
            result.append(text)
            hide_next = True
            continue
        result.append(redact(item))
    return result


def redact(value: Any, *, key: str = "") -> Any:
    if key and SENSITIVE_KEY.search(key):
        return _placeholder("redacted", value)
    if isinstance(value, dict):
        return {str(name): redact(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return _redact_command(value) if key.lower() in {"command", "argv", "args"} else [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(str(value))


def build_diagnostic_report(
    audit: Any = None,
    manifest: Any = None,
    plan: Any = None,
    phases: Any = None,
    warnings: Any = None,
    *,
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = report if report is not None else {
        "audit": audit,
        "manifest": manifest,
        "plan": plan,
        "phases": phases,
        "warnings": warnings,
    }
    result = redact(source)
    return result if isinstance(result, dict) else {"report": result}
