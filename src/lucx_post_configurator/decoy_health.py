from __future__ import annotations

import socket
import ssl
from typing import Any

from .decoy_capabilities import classify_decoy_capabilities


MAX_RESPONSE_BYTES = 8192


def evaluate_http_response(
    response: bytes,
    expected_marker: str | None,
) -> dict[str, Any]:
    header_block = response.split(b"\r\n\r\n", 1)[0]
    lines = header_block.split(b"\r\n")
    try:
        status_line = lines[0].decode("ascii")
        fields = status_line.split()
        status = int(fields[1]) if len(fields) >= 2 and fields[0].startswith("HTTP/") else 0
    except (UnicodeDecodeError, ValueError):
        status = 0
    if not 200 <= status < 400:
        return {
            "state": "http_error",
            "status": status,
            "detail": status_line if status else "invalid HTTP response",
        }
    if expected_marker is not None:
        marker = expected_marker.encode("ascii").lower()
        if marker not in header_block.lower():
            return {
                "state": "http_error",
                "status": status,
                "detail": "managed marker is absent",
            }
        return {
            "state": "healthy",
            "status": status,
            "detail": "managed marker observed",
        }
    return {
        "state": "site_observed",
        "status": status,
        "detail": "HTTPS response observed",
    }


def observe_decoy(
    domain: str,
    address: str,
    port: int,
    expected_marker: str | None,
    timeout: float = 10.0,
    *,
    use_tls: bool = True,
) -> dict[str, Any]:
    try:
        with socket.create_connection((address, int(port)), timeout=timeout) as raw_socket:
            stream: Any = raw_socket
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                stream = context.wrap_socket(raw_socket, server_hostname=domain)
            try:
                stream.sendall(
                    (
                        f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
                        "User-Agent: lucx-post-configurator-health\r\n"
                        "Accept: text/html,*/*;q=0.1\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                response = bytearray()
                while len(response) < MAX_RESPONSE_BYTES:
                    chunk = stream.recv(min(2048, MAX_RESPONSE_BYTES - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if b"\r\n\r\n" in response:
                        break
            finally:
                if use_tls:
                    stream.close()
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"state": "tls_error", "status": 0, "detail": str(exc)}
    return evaluate_http_response(bytes(response), expected_marker)


def decoy_probe_targets(manifest: dict[str, Any], public_address: str) -> list[dict[str, Any]]:
    decoys = manifest.get("decoys") or {}
    current_sites = {
        str(item.get("domain") or "").lower(): item
        for item in decoys.get("sites") or []
        if item.get("domain")
    }
    capabilities = list(decoys.get("capabilities") or [])
    if current_sites:
        by_domain = {str(item.get("domain") or "").lower(): item for item in capabilities}
        # A blocked route keeps its SNI on the VPN backend; probing it as a
        # managed decoy would fail with a protocol error and roll back a
        # healthy transaction.
        blocked_domains = {
            str(route.get("domain") or "").lower()
            for route in decoys.get("extended_routes") or []
            if str(route.get("status") or "") != "ready"
            and str(route.get("strategy") or "") not in {"", "ready"}
        }
        capabilities = [
            by_domain.get(
                domain,
                {
                    "domain": domain,
                    "managed": domain not in blocked_domains,
                    "probe_mode": "none" if domain in blocked_domains else "active",
                },
            )
            for domain in current_sites
        ]
    if not capabilities:
        capabilities = classify_decoy_capabilities(manifest)
    extended = str(decoys.get("routing_mode") or "strict") == "extended"
    public_port = int(manifest["network"]["public_tcp_port"])
    targets: list[dict[str, Any]] = []
    for item in capabilities:
        if not item.get("managed") or str(item.get("probe_mode") or "none") == "none":
            continue
        domain = str(item["domain"])
        targets.append(
            {
                "domain": domain,
                "path": "public_tls",
                "address": public_address,
                "port": public_port,
                "tls": True,
            }
        )
        if extended:
            host = str(decoys.get("listen_host") or "127.0.0.1")
            port = int(decoys.get("listen_port") or 8444)
            targets.extend(
                [
                    {
                        "domain": domain,
                        "path": "internal_tls",
                        "address": host,
                        "port": port,
                        "tls": True,
                    },
                    {
                        "domain": domain,
                        "path": "internal_h2c",
                        "address": host,
                        "port": port + 1,
                        "tls": False,
                    },
                ]
            )
    return targets


def observe_decoy_capabilities(
    manifest: dict[str, Any],
    address: str,
    *,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    capabilities = list((manifest.get("decoys") or {}).get("capabilities") or [])
    if not capabilities:
        capabilities = classify_decoy_capabilities(manifest)
    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        results: list[dict[str, Any]] = []
        for target in decoy_probe_targets(manifest, address):
            domain = str(target["domain"])
            result = observe_decoy(
                domain,
                str(target["address"]),
                int(target["port"]),
                f"X-LucX-Decoy: {domain}",
                timeout,
                use_tls=bool(target["tls"]),
            )
            results.append(
                {
                    "domain": domain,
                    "capability_status": "extended_ready",
                    "managed": True,
                    "path": target["path"],
                    "state": result["state"],
                    "http_status": int(result.get("status") or 0),
                    "detail": result["detail"],
                }
            )
        blocked_domains = {
            str(item["domain"])
            for item in capabilities
            if not item.get("managed") or str(item.get("probe_mode") or "none") == "none"
        }
        results.extend(
            {
                "domain": domain,
                "capability_status": "extended_blocked",
                "managed": False,
                "path": "none",
                "state": "skipped",
                "http_status": 0,
                "detail": "unsafe topology",
            }
            for domain in sorted(blocked_domains)
        )
        return results

    port = int(manifest["network"]["public_tcp_port"])
    results: list[dict[str, Any]] = []
    for item in capabilities:
        probe_mode = str(item.get("probe_mode") or "none")
        if probe_mode == "none":
            result = {"state": "skipped", "status": 0, "detail": "unsafe topology"}
        else:
            domain = str(item["domain"])
            marker = f"X-LucX-Decoy: {domain}" if item.get("managed") else None
            result = observe_decoy(domain, address, port, marker, timeout)
        results.append(
            {
                "domain": item["domain"],
                "capability_status": item["status"],
                "managed": bool(item.get("managed")),
                "state": result["state"],
                "http_status": int(result.get("status") or 0),
                "detail": result["detail"],
            }
        )
    return results
