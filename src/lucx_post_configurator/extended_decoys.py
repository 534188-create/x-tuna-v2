from __future__ import annotations

import re
from typing import Any

from .models import Audit, valid_domain


HTTP_TRANSPORTS = {"ws", "httpupgrade", "grpc"}
AMBIGUOUS_HTTP_TRANSPORTS = {"http"}
XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
BINARY_TLS_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks", "anytls"}
SEPARATE_PORT_PROTOCOLS = {"mieru", "qwdtt"}
TRUSTTUNNEL_PROTOCOLS = {"trusttunnel", "trust-tunnel"}
CLIENTHELLO_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{12,64}$", re.IGNORECASE)


def exact_client_random_prefix(value: Any) -> str:
    """Return an exact byte prefix, rejecting masks HAProxy cannot preserve."""

    text = str(value or "").strip().lower()
    if not text:
        return ""
    prefix, separator, mask = text.partition("/")
    if not re.fullmatch(r"[0-9a-f]{2,64}", prefix) or len(prefix) % 2:
        return ""
    if separator and (len(mask) != len(prefix) or set(mask) != {"f"}):
        return ""
    return prefix.upper()


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _bindings(protocol: dict[str, Any], transport: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in protocol.get("port_bindings") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("protocol") or "").upper()
        if transport == "udp" and name not in {"UDP", "TCP_UDP"}:
            continue
        if transport == "tcp" and name not in {"TCP", "TCP_UDP"}:
            continue
        safe: dict[str, Any] = {"protocol": name}
        port = _integer(item.get("port"))
        if 1 <= port <= 65535:
            safe["port"] = port
        port_range = str(item.get("port_range") or "")
        if re.fullmatch(r"\d{1,5}-\d{1,5}", port_range):
            safe["port_range"] = port_range
        if len(safe) > 1 and safe not in result:
            result.append(safe)
    return result


def _owns_tcp_port(protocol: dict[str, Any], port: int) -> bool:
    if _text(protocol.get("network")) in {"tcp", "both"} and _integer(
        protocol.get("public_port")
    ) == port:
        return True
    return any(_integer(item.get("port")) == port for item in _bindings(protocol, "tcp"))


def _naive_metadata(audit: Audit | None, inbound_id: int) -> dict[str, Any] | None:
    if audit is None:
        return None
    files = audit.naive_caddyfile.get("files") or []
    suffix = f"/naive-{inbound_id}.caddyfile"
    for item in files:
        if isinstance(item, dict) and str(item.get("path") or "").endswith(suffix):
            return item
    if len(files) == 1 and isinstance(files[0], dict):
        return files[0]
    return None


def _base_route(protocol: dict[str, Any], shared_tcp_port: int) -> dict[str, Any]:
    domain = _text(protocol.get("domain"))
    udp_bindings = _bindings(protocol, "udp")
    network = _text(protocol.get("network"))
    return {
        "inbound_id": _integer(protocol.get("inbound_id")),
        "protocol": _text(protocol.get("protocol")) or "unknown",
        "domain": domain,
        "strategy": "blocked_unknown",
        "status": "blocked",
        "managed": False,
        "reason": "Топология не доказана; внешний маршрут не создаётся.",
        "evidence": [],
        "network": network,
        "security": _text(protocol.get("security")),
        "transport": _text(protocol.get("transport")) or "tcp",
        "internal_host": str(protocol.get("internal_host") or "127.0.0.1"),
        "internal_port": _integer(protocol.get("internal_port")),
        "public_tcp_port": shared_tcp_port,
        "sni_names": list(dict.fromkeys(_text(value) for value in protocol.get("sni_names") or [] if _text(value))),
        "transport_path": str(protocol.get("transport_path") or ""),
        "transport_mode": _text(protocol.get("transport_mode")),
        "transport_hosts": list(
            dict.fromkeys(
                _text(value) for value in protocol.get("transport_hosts") or [] if _text(value)
            )
        ),
        "alpn": list(dict.fromkeys(str(value) for value in protocol.get("alpn") or [] if value)),
        "tls_termination": False,
        "backend_tls": False,
        "vpn_action": "unchanged",
        "browser_action": "none",
        "existing_udp_bindings": udp_bindings,
        "managed_udp_bindings": [],
        "preserves_udp": network in {"udp", "both"} or bool(udp_bindings),
        "preflight_required": False,
    }


def _ready(
    route: dict[str, Any],
    strategy: str,
    reason: str,
    *,
    tls_termination: bool = False,
    backend_tls: bool = False,
    vpn_action: str = "unchanged",
    preflight_required: bool = False,
) -> dict[str, Any]:
    route.update(
        {
            "strategy": strategy,
            "status": "ready",
            "managed": True,
            "reason": reason,
            "tls_termination": tls_termination,
            "backend_tls": backend_tls,
            "vpn_action": vpn_action,
            "browser_action": "decoy",
            "preflight_required": preflight_required,
        }
    )
    return route


def _blocked(route: dict[str, Any], reason: str) -> dict[str, Any]:
    route["reason"] = reason
    route["evidence"].append("VPN route retained; no browser ingress is published")
    return route


def classify_extended_decoy_routes(
    manifest: dict[str, Any], audit: Audit | None = None
) -> list[dict[str, Any]]:
    """Return deterministic, secret-free routes for the opt-in extended mode."""

    shared_tcp_port = _integer((manifest.get("network") or {}).get("public_tcp_port"))
    if not 1 <= shared_tcp_port <= 65535:
        shared_tcp_port = 443

    routes: list[dict[str, Any]] = []
    for protocol in manifest.get("protocols") or []:
        if not isinstance(protocol, dict):
            continue
        route = _base_route(protocol, shared_tcp_port)
        name = route["protocol"]
        domain = route["domain"]
        security = route["security"]
        transport = route["transport"]
        tls_protocol = security == "tls" or name == "anytls"
        sni_names = set(route["sni_names"])
        route["evidence"].append(
            f"inbound #{route['inbound_id']} protocol={name} network={route['network']} transport={transport} security={security or 'none'}"
        )

        if route["inbound_id"] <= 0 or not valid_domain(domain):
            routes.append(_blocked(route, "Некорректный inbound ID или endpoint-домен."))
            continue

        if name in SEPARATE_PORT_PROTOCOLS:
            if _owns_tcp_port(protocol, shared_tcp_port):
                routes.append(
                    _blocked(
                        route,
                        f"{name} уже владеет TCP/{shared_tcp_port}; безопасное разделение не доказано.",
                    )
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "tcp_side_site",
                        f"{name} остаётся на исходном порту; TCP/{shared_tcp_port} используется только сайтом.",
                    )
                )
            continue

        if route["network"] == "udp" and not bool(protocol.get("udp_over_tcp")):
            routes.append(
                _ready(
                    route,
                    "tcp_side_site",
                    f"VPN использует UDP; отдельный TCP/{shared_tcp_port} не меняет его listener.",
                )
            )
            continue

        if security == "reality":
            if domain and domain not in sni_names:
                routes.append(
                    _ready(
                        route,
                        "reality_endpoint_site",
                        "Endpoint SNI свободен, а Reality camouflage SNI остаётся passthrough.",
                        vpn_action="passthrough",
                    )
                )
            else:
                routes.append(
                    _blocked(
                        route,
                        "Endpoint-домен совпадает с Reality SNI; браузер и VPN нельзя различить безопасно.",
                    )
                )
            continue

        if name == "naive":
            metadata = _naive_metadata(audit, route["inbound_id"])
            if metadata is None:
                routes.append(
                    _blocked(route, "Исходный Naive Caddyfile не найден; frontend нельзя построить безопасно.")
                )
                continue
            capabilities = metadata.get("capabilities") or {}
            binary_path = str((audit.naive_caddyfile if audit else {}).get("binary_path") or "")
            route["source_caddyfile"] = str(metadata.get("path") or "")
            route["source_caddyfile_sha256"] = str(metadata.get("sha256") or "")
            if capabilities.get("native_decoy") is True:
                route["naive_mode"] = "native"
                routes.append(
                    _ready(
                        route,
                        "naive_native",
                        "Штатный Naive frontend поддерживает forward proxy и сайт одновременно.",
                        vpn_action="passthrough",
                    )
                )
            elif capabilities.get("forward_proxy") is True:
                if not binary_path.startswith("/"):
                    route["naive_mode"] = "blocked"
                    routes.append(
                        _blocked(route, "Исполняемый файл штатного Naive Caddy не найден.")
                    )
                else:
                    route["naive_mode"] = "managed"
                    route["binary_path"] = binary_path
                    routes.append(
                        _ready(
                            route,
                            "naive_managed",
                            "Требуется отдельный управляемый frontend; исходный Caddyfile остаётся неизменным.",
                            vpn_action="passthrough",
                            preflight_required=True,
                        )
                    )
            else:
                route["naive_mode"] = "blocked"
                routes.append(
                    _blocked(route, "Структура Naive Caddyfile не подтверждает forward proxy.")
                )
            continue

        if name in TRUSTTUNNEL_PROTOCOLS:
            fingerprint = _text(protocol.get("clienthello_match_fingerprint"))
            if CLIENTHELLO_FINGERPRINT_RE.fullmatch(fingerprint):
                route["clienthello_match_fingerprint"] = fingerprint
                routes.append(
                    _ready(
                        route,
                        "trusttunnel_clienthello_split",
                        "VPN ClientHello имеет подтверждённый matcher; остальные TLS-запросы идут на сайт.",
                        vpn_action="passthrough",
                        preflight_required=True,
                    )
                )
            else:
                routes.append(
                    _blocked(route, "Для TrustTunnel не получен безопасный отпечаток ClientHello matcher.")
                )
            continue

        if tls_protocol and transport == "xhttp" and name in BINARY_TLS_PROTOCOLS:
            path = str(route.get("transport_path") or "").split("?", 1)[0].strip()
            mode = route.get("transport_mode") or "auto"
            route["transport_mode"] = mode
            if not path.startswith("/") or path == "/":
                routes.append(
                    _blocked(
                        route,
                        "XHTTP для общего TCP/443 требует отдельный непустой path; '/' забрал бы браузерный корень у сайта.",
                    )
                )
            elif mode not in XHTTP_MODES:
                routes.append(
                    _blocked(route, f"Неизвестный режим XHTTP {mode}; конфигурация сохраняется без изменений.")
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "xhttp_tls_split",
                        "XHTTP использует отдельный path; корень домена обслуживает сайт.",
                        tls_termination=True,
                        backend_tls=True,
                        vpn_action="tls_reencrypt",
                        preflight_required=True,
                    )
                )
            continue

        if (
            tls_protocol
            and transport in AMBIGUOUS_HTTP_TRANSPORTS
            and name in BINARY_TLS_PROTOCOLS
        ):
            routes.append(
                _blocked(
                    route,
                    f"HTTP transport {transport} не имеет доказанного признака, отделяющего VPN от браузера.",
                )
            )
            continue

        if tls_protocol and transport in HTTP_TRANSPORTS and name in BINARY_TLS_PROTOCOLS:
            path = str(route.get("transport_path") or "").split("?", 1)[0].strip()
            if not path or path == "/":
                # ws/httpupgrade with a root path cannot safely distinguish a
                # browser GET from a VPN upgrade request on the same SNI.
                routes.append(
                    _blocked(
                        route,
                        f"HTTP transport {transport} с path=/ нельзя безопасно разделить с браузером; задайте отдельный путь в LucX.",
                    )
                )
                continue
            routes.append(
                _ready(
                    route,
                    "http_tls_split",
                    "HTTP transport маршрутизируется по path/host после TLS termination.",
                    tls_termination=True,
                    backend_tls=True,
                    vpn_action="tls_reencrypt",
                    preflight_required=True,
                )
            )
            continue

        if tls_protocol and name in BINARY_TLS_PROTOCOLS:
            if domain not in sni_names:
                routes.append(
                    _blocked(route, "TLS endpoint SNI не подтверждён данными LucX/Hosts.")
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "binary_tls_split",
                        "Обычный HTTP обслуживает сайт; бинарный TLS поток повторно шифруется до inbound.",
                        tls_termination=True,
                        backend_tls=True,
                        vpn_action="tls_reencrypt",
                        preflight_required=True,
                    )
                )
            continue

        routes.append(
            _blocked(
                route,
                f"Для protocol={name}, transport={transport}, security={security or 'none'} нет доказанной стратегии.",
            )
        )

    occupied = {
        shared_tcp_port,
        _integer(manifest.get("lucx", {}).get("panel", {}).get("internal_port")),
        _integer(manifest.get("lucx", {}).get("subscription", {}).get("internal_port")),
        _integer(manifest.get("decoys", {}).get("listen_port")),
        _integer(manifest.get("decoys", {}).get("listen_port")) + 1,
    }
    occupied.update(
        _integer(item.get("internal_port")) for item in manifest.get("protocols") or []
    )
    ranges: list[tuple[int, int]] = []
    for item in manifest.get("protocols") or []:
        for binding in item.get("port_bindings") or []:
            port_range = str(binding.get("port_range") or "")
            if re.fullmatch(r"\d{1,5}-\d{1,5}", port_range):
                low, high = (int(value) for value in port_range.split("-", 1))
                ranges.append((low, high))
    candidate = 26443
    for route in sorted(
        (item for item in routes if item.get("strategy") == "naive_managed"),
        key=lambda item: int(item.get("inbound_id") or 0),
    ):
        while candidate <= 65535 and (
            candidate in occupied or any(low <= candidate <= high for low, high in ranges)
        ):
            candidate += 1
        if candidate > 65535:
            route.update(
                {
                    "strategy": "blocked_unknown",
                    "status": "blocked",
                    "managed": False,
                    "naive_mode": "blocked",
                    "reason": "Нет свободного loopback TCP-порта для управляемого Naive frontend.",
                }
            )
            continue
        route["managed_listen_port"] = candidate
        occupied.add(candidate)
        candidate += 1
    return routes
