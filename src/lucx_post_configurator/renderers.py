from __future__ import annotations

import dataclasses
import hashlib
import importlib.resources
import ipaddress
import re
import shlex
from typing import Any

from .decoy_capabilities import managed_decoy_domains
from .models import validate_manifest, valid_domain


@dataclasses.dataclass(frozen=True, slots=True)
class GeneratedFile:
    content: bytes = b""
    mode: int = 0o644
    component: str = "core"
    symlink_target: str = ""


def _acl_name(prefix: str, value: str) -> str:
    clean = re.sub(r"[^a-z0-9_]", "_", value.lower())
    return f"{prefix}_{clean}"[:60]


def _backend_host(value: str) -> str:
    value = str(value or "127.0.0.1").strip()
    if value in {"", "0.0.0.0", "::", "[::]", "localhost"}:
        return "127.0.0.1"
    try:
        parsed = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", value):
            raise ValueError(f"unsafe backend host: {value}")
        return value
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


def _render_haproxy_strict(manifest: dict[str, Any]) -> str:
    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    sidecar_enabled = manifest["components"].get("sidecar", False)
    public_port = int(manifest["network"]["public_tcp_port"])
    panel_public_port = int(panel.get("public_port", public_port))
    subscription_public_port = int(subscription.get("public_port", public_port))
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    bind_address = str(manifest["network"]["public_bind_address"])
    if bind_address in {"0.0.0.0", "::"}:
        bind_host = "*"
    elif ":" in bind_address:
        bind_host = f"[{bind_address}]"
    else:
        bind_host = bind_address
    groups: dict[int, list[tuple[str, str, str, int]]] = {}
    groups.setdefault(panel_public_port, []).append(
        (panel["domain"], "be_panel", _backend_host(panel["internal_host"]), int(panel["internal_port"]))
    )
    groups.setdefault(subscription_public_port, []).append(
        (
            subscription["domain"],
            "be_subscription",
            _backend_host(manifest["sidecar"]["listen_host"] if sidecar_enabled else subscription["internal_host"]),
            int(manifest["sidecar"]["listen_port"] if sidecar_enabled else subscription["internal_port"]),
        )
    )
    for protocol in manifest["protocols"]:
        if protocol["exposure"] == "tcp_sni":
            group = groups.setdefault(int(protocol["public_port"]), [])
            for sni in protocol.get("sni_names") or [protocol["domain"]]:
                group.append(
                    (
                        sni,
                        f"be_inbound_{protocol['inbound_id']}",
                        _backend_host(protocol["internal_host"]),
                        int(protocol["internal_port"]),
                    )
                )

    route_domains = {item[0] for item in groups.get(public_port, [])}
    if manifest["decoys"].get("enabled"):
        sites = {site["domain"] for site in manifest["decoys"].get("sites", [])}
        for domain in [
            value
            for value in managed_decoy_domains(manifest)
            if value in sites and value not in route_domains
        ]:
            groups.setdefault(public_port, []).append(
                (
                    domain,
                    "be_decoy",
                    _backend_host(manifest["decoys"]["listen_host"]),
                    int(manifest["decoys"]["listen_port"]),
                )
            )

    lines = [
        "# Managed by lucx-post-configurator. Local edits will be replaced.",
        "global",
        "    log /dev/log local0",
        "    log /dev/log local1 notice",
        "    user haproxy",
        "    group haproxy",
        "    daemon",
        "",
        "defaults",
        "    log global",
        "    mode tcp",
        "    option tcplog",
        "    timeout connect 5s",
        "    timeout client 1m",
        "    timeout server 1m",
    ]
    non_tls_id = manifest["network"].get("non_tls_backend_inbound_id")
    non_tls = next((p for p in manifest["protocols"] if p["inbound_id"] == non_tls_id), None)
    unique_backends: dict[str, tuple[str, int]] = {}

    for frontend_port, routes in sorted(groups.items()):
        known_sni_acl = _acl_name("known_sni", str(frontend_port))
        lines.extend(
            [
                "",
                f"frontend lucx_tls_{frontend_port}",
                f"    bind {bind_host}:{frontend_port}",
                "    mode tcp",
                "    tcp-request inspect-delay 5s",
                "    acl is_tls req.ssl_hello_type 1",
            ]
        )
        route_rules: list[tuple[str, str]] = []
        acls: list[str] = []
        for route_index, (domain, backend, host, port) in enumerate(routes, start=1):
            acl = _acl_name(f"sni_{frontend_port}_{route_index}", domain)
            acls.append(acl)
            lines.append(f"    acl {acl} req.ssl_sni -i {domain}")
            lines.append(f"    acl {known_sni_acl} req.ssl_sni -i {domain}")
            route_rules.append((backend, acl))
            previous = unique_backends.get(backend)
            if previous and previous != (host, port):
                raise ValueError(f"backend {backend} has conflicting targets")
            unique_backends[backend] = (host, port)

        protected_routes = [
            (backend, acl)
            for backend, acl in route_rules
            if backend in {"be_panel", "be_subscription"}
        ]
        if cloudflare_only and protected_routes:
            lines.append("    acl from_cloudflare src -f /etc/haproxy/cloudflare-ips.lst")
            local_sources = ["127.0.0.0/8", "::1"]
            if bind_address not in {"0.0.0.0", "::"}:
                local_sources.append(bind_address)
            lines.append("    acl from_local_health src " + " ".join(local_sources))
            for backend, acl in protected_routes:
                lines.append(
                    f"    tcp-request content reject if is_tls {acl} !from_cloudflare !from_local_health"
                )

        unknown_to_decoy = (
            frontend_port == public_port
            and manifest["network"].get("unknown_sni_action") == "decoy"
        )
        if not unknown_to_decoy and acls:
            lines.append(f"    tcp-request content reject if is_tls !{known_sni_acl}")
        group_non_tls = non_tls if non_tls and int(non_tls["public_port"]) == frontend_port else None
        if not group_non_tls:
            # WAIT_END prevents eager rejection before ClientHello arrives.
            lines.append("    tcp-request content reject if !is_tls WAIT_END")
        lines.append("    tcp-request content accept if is_tls")
        for backend, acl in route_rules:
            lines.append(f"    use_backend {backend} if {acl}")
        if unknown_to_decoy:
            lines.append("    use_backend be_decoy if is_tls")
            unique_backends.setdefault(
                "be_decoy",
                (
                    _backend_host(manifest["decoys"]["listen_host"]),
                    int(manifest["decoys"]["listen_port"]),
                ),
            )
        if group_non_tls:
            lines.append(f"    use_backend be_inbound_{non_tls_id} if !is_tls")

    if non_tls:
        unique_backends.setdefault(
            f"be_inbound_{non_tls_id}",
            (_backend_host(non_tls["internal_host"]), int(non_tls["internal_port"])),
        )
    for backend, (host, port) in unique_backends.items():
        lines.extend(["", f"backend {backend}", "    mode tcp", f"    server local {host}:{port}"])
    return "\n".join(lines) + "\n"


def _safe_clienthello_prefix(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2,64}", text) or len(text) % 2:
        raise ValueError("unsafe TrustTunnel routing material")
    return text


def _safe_http_path(value: Any, inbound_id: int) -> str:
    path = str(value or "").split("?", 1)[0]
    if not path.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path):
        raise ValueError(f"HTTP transport path is missing or unsafe for inbound #{inbound_id}")
    return path


def extended_split_ports(manifest: dict[str, Any], routes: list[dict[str, Any]]) -> dict[int, int]:
    occupied = {
        int(manifest["network"]["public_tcp_port"]),
        int(manifest["decoys"]["listen_port"]),
        int(manifest["decoys"]["listen_port"]) + 1,
        int(manifest["lucx"]["panel"]["internal_port"]),
        int(manifest["lucx"]["subscription"]["internal_port"]),
    }
    occupied.update(
        int(item.get("internal_port") or 0)
        for item in manifest.get("protocols") or []
        if 1 <= int(item.get("internal_port") or 0) <= 65535
    )
    occupied.update(
        int(item.get("managed_listen_port") or 0)
        for item in routes
        if 1 <= int(item.get("managed_listen_port") or 0) <= 65535
    )
    result: dict[int, int] = {}
    candidate = int((manifest.get("decoys") or {}).get("tls_split_port_start") or 24443)
    for route in sorted(
        (
            item
            for item in routes
            if item.get("strategy") in {"http_tls_split", "xhttp_tls_split", "binary_tls_split"}
        ),
        key=lambda item: int(item.get("inbound_id") or 0),
    ):
        while candidate in occupied and candidate <= 65535:
            candidate += 1
        if candidate > 65535:
            raise ValueError("no free loopback port remains for extended TLS split")
        inbound_id = int(route["inbound_id"])
        result[inbound_id] = candidate
        occupied.add(candidate)
        candidate += 1
    return result


def _render_haproxy_extended(
    manifest: dict[str, Any], routing_material: dict[int | str, dict[str, Any]] | None
) -> str:
    routes = list((manifest.get("decoys") or {}).get("extended_routes") or [])
    if not routes:
        from .extended_decoys import classify_extended_decoy_routes

        routes = classify_extended_decoy_routes(manifest)
    # Omit ambiguous routes instead of letting them steal browser traffic or
    # blocking an otherwise safe apply for unrelated inbound configurations.
    blocked_passthrough = []
    for item in routes:
        if str(item.get("status") or "blocked") == "ready":
            continue
        # Keep an ambiguous XHTTP SNI on its VPN backend. Its browser decoy
        # remains unavailable until the user assigns a non-root XHTTP path.
        if (
            str(item.get("transport") or "").lower() == "xhttp"
            and str(item.get("transport_path") or "/") == "/"
        ):
            passthrough = dict(item)
            passthrough["strategy"] = "blocked_passthrough"
            blocked_passthrough.append(passthrough)
    routes = [item for item in routes if str(item.get("status") or "blocked") == "ready"]
    routes.extend(blocked_passthrough)

    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    sidecar_enabled = bool(manifest["components"].get("sidecar"))
    public_port = int(manifest["network"]["public_tcp_port"])
    bind_address = str(manifest["network"]["public_bind_address"])
    bind_host = "*" if bind_address in {"0.0.0.0", "::"} else (
        f"[{bind_address}]" if ":" in bind_address else bind_address
    )
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    split_ports = extended_split_ports(manifest, routes)
    by_id = {int(item["inbound_id"]): item for item in manifest.get("protocols") or []}
    decoy_host = _backend_host(manifest["decoys"]["listen_host"])
    decoy_tls_port = int(manifest["decoys"]["listen_port"])
    decoy_h2c_port = decoy_tls_port + 1

    groups: dict[int, list[tuple[str, str, bool]]] = {}
    backends: dict[str, tuple[str, int, str, str]] = {}

    def backend(
        name: str, host: str, port: int, options: str = "", mode: str = "tcp"
    ) -> None:
        target = (host, port, options, mode)
        previous = backends.get(name)
        if previous is not None and previous != target:
            raise ValueError(f"backend {name} has conflicting targets")
        backends[name] = target

    def sni_route(port: int, domain: str, target: str, protected: bool = False) -> None:
        normalized = str(domain or "").strip().lower().rstrip(".")
        if not normalized:
            raise ValueError("empty SNI in extended route")
        group = groups.setdefault(port, [])
        for existing_domain, existing_target, _ in group:
            if existing_domain == normalized and existing_target != target:
                raise ValueError(
                    f"conflicting extended SNI {normalized}: {existing_target} versus {target}"
                )
        item = (normalized, target, protected)
        if item not in group:
            group.append(item)

    panel_port = int(panel.get("public_port", public_port))
    subscription_port = int(subscription.get("public_port", public_port))
    backend("be_panel", _backend_host(panel["internal_host"]), int(panel["internal_port"]))
    backend(
        "be_subscription",
        _backend_host(
            manifest["sidecar"]["listen_host"] if sidecar_enabled else subscription["internal_host"]
        ),
        int(manifest["sidecar"]["listen_port"] if sidecar_enabled else subscription["internal_port"]),
    )
    sni_route(panel_port, panel["domain"], "be_panel", True)
    sni_route(subscription_port, subscription["domain"], "be_subscription", True)
    backend("be_decoy_tls", decoy_host, decoy_tls_port)
    backend("be_decoy_h2c", decoy_host, decoy_h2c_port)
    backend("be_decoy_h2c_http", decoy_host, decoy_h2c_port, "proto h2", "http")
    compatible_backend = manifest.get("trusttunnel_backend") or {}
    if manifest["components"].get("trusttunnel_backend"):
        backend(
            "be_trusttunnel_compatible",
            "127.0.0.1",
            int(compatible_backend["listen_port"]),
        )

    trust_rules: dict[int, list[tuple[str, str, int]]] = {}
    for route in routes:
        inbound_id = int(route["inbound_id"])
        protocol = by_id.get(inbound_id)
        if protocol is None:
            raise ValueError(f"extended route refers to missing inbound #{inbound_id}")
        strategy = str(route["strategy"])
        domain = str(route["domain"])
        names = list(dict.fromkeys([domain, *(route.get("sni_names") or [])]))
        inbound_backend = f"be_inbound_{inbound_id}"
        inbound_host = _backend_host(route.get("internal_host") or protocol.get("internal_host"))
        inbound_port = int(route.get("internal_port") or protocol.get("internal_port"))

        # The compatible endpoint terminates TLS itself and owns only its
        # explicitly confirmed SNI. Its internal LucX listener remains intact
        # for rollback and is not placed behind this public route.
        if (
            manifest["components"].get("trusttunnel_backend")
            and domain.lower() == str(compatible_backend.get("public_domain") or "").lower()
        ):
            sni_route(public_port, domain, "be_trusttunnel_compatible")
            continue

        if strategy == "tcp_side_site":
            sni_route(public_port, domain, "be_decoy_tls")
        elif strategy == "reality_endpoint_site":
            sni_route(public_port, domain, "be_decoy_tls")
            backend(inbound_backend, inbound_host, inbound_port)
            for name in route.get("sni_names") or []:
                sni_route(public_port, str(name), inbound_backend)
        elif strategy in {"http_tls_split", "xhttp_tls_split", "binary_tls_split"}:
            split_backend = f"be_split_{inbound_id}"
            backend(split_backend, "127.0.0.1", split_ports[inbound_id])
            for name in names:
                sni_route(public_port, str(name), split_backend)
        elif strategy == "trusttunnel_clienthello_split":
            material = (routing_material or {}).get(inbound_id) or (routing_material or {}).get(
                str(inbound_id)
            )
            if not isinstance(material, dict):
                raise ValueError(f"TrustTunnel inbound #{inbound_id} routing material is unavailable")
            prefix = _safe_clienthello_prefix(material.get("clienthello_hex_prefix"))
            backend(inbound_backend, inbound_host, inbound_port)
            trust_rules.setdefault(public_port, []).append(
                (f"trust_clienthello_{inbound_id}", prefix, len(prefix) // 2)
            )
            for name in names:
                sni_route(public_port, str(name), "be_decoy_tls")
        elif strategy == "blocked_passthrough":
            backend(inbound_backend, inbound_host, inbound_port)
            for name in names:
                sni_route(public_port, str(name), inbound_backend)
        elif strategy in {"naive_native", "naive_managed"}:
            target_port = inbound_port
            target_name = inbound_backend
            if strategy == "naive_managed":
                target_port = int(route["managed_listen_port"])
                target_name = f"be_naive_frontend_{inbound_id}"
                # The generated managed Caddyfile always binds loopback even
                # when the original LucX listener used another address.
                backend(target_name, "127.0.0.1", target_port)
            else:
                backend(target_name, inbound_host, target_port)
            for name in names:
                sni_route(public_port, str(name), target_name)
        else:
            raise ValueError(f"unsupported ready extended strategy: {strategy}")

    # Standalone decoy sites (for example the DNS zone root) are not owned by
    # any inbound: they always serve the Nginx decoy frontend.
    routed_domains = {str(item.get("domain") or "").lower() for item in routes}
    routed_snis = {
        str(name).lower()
        for item in routes
        for name in [item.get("domain"), *(item.get("sni_names") or [])]
        if name
    }
    for site in (manifest.get("decoys") or {}).get("sites") or []:
        domain = str(site.get("domain") or "").lower().rstrip(".")
        if not domain or valid_domain(domain) is False:
            continue
        if domain in routed_domains or domain in routed_snis:
            continue
        sni_route(public_port, domain, "be_decoy_tls")

    lines = [
        "# Managed by lucx-post-configurator. Local edits will be replaced.",
        "global",
        "    log /dev/log local0",
        "    log /dev/log local1 notice",
        "    user haproxy",
        "    group haproxy",
        "    daemon",
        "",
        "defaults",
        "    log global",
        "    mode tcp",
        "    option tcplog",
        "    timeout connect 5s",
        "    timeout client 1m",
        "    timeout server 1m",
    ]

    for frontend_port, group in sorted(groups.items()):
        known_sni_acl = _acl_name("known_sni", str(frontend_port))
        lines.extend(
            [
                "",
                f"frontend lucx_tls_{frontend_port}",
                f"    bind {bind_host}:{frontend_port}",
                "    mode tcp",
                "    tcp-request inspect-delay 5s",
                "    acl is_tls req.ssl_hello_type 1",
            ]
        )
        acl_routes: list[tuple[str, str, bool]] = []
        for index, (domain, target, protected) in enumerate(group, start=1):
            acl = _acl_name(f"sni_{frontend_port}_{index}", domain)
            lines.append(f"    acl {acl} req.ssl_sni -i {domain}")
            lines.append(f"    acl {known_sni_acl} req.ssl_sni -i {domain}")
            acl_routes.append((target, acl, protected))
        for acl, prefix, length in trust_rules.get(frontend_port, []):
            lines.append(f"    acl {acl} req.payload(11,{length}),hex -m str {prefix}")
        protected_routes = [item for item in acl_routes if item[2]]
        if cloudflare_only and protected_routes:
            lines.append("    acl from_cloudflare src -f /etc/haproxy/cloudflare-ips.lst")
            local_sources = ["127.0.0.0/8", "::1"]
            if bind_address not in {"0.0.0.0", "::"}:
                local_sources.append(bind_address)
            lines.append("    acl from_local_health src " + " ".join(local_sources))
            for _target, acl, _protected in protected_routes:
                lines.append(
                    f"    tcp-request content reject if is_tls {acl} !from_cloudflare !from_local_health"
                )
        all_acls = [item[1] for item in acl_routes]
        if all_acls:
            lines.append(f"    tcp-request content reject if is_tls !{known_sni_acl}")
        lines.append("    tcp-request content reject if !is_tls WAIT_END")
        lines.append("    tcp-request content accept if is_tls")
        for acl, _prefix, _length in trust_rules.get(frontend_port, []):
            inbound_id = int(acl.rsplit("_", 1)[1])
            lines.append(f"    use_backend be_inbound_{inbound_id} if {acl}")
        for target, acl, _protected in acl_routes:
            lines.append(f"    use_backend {target} if {acl}")

    certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
    h2_preface = "505249202A20485454502F322E300D0A0D0A534D0D0A0D0A"
    http1_prefixes = (
        "47455420",
        "4845414420",
        "504F535420",
        "50555420",
        "504154434820",
        "4F5054494F4E5320",
        "44454C45544520",
        "434F4E4E45435420",
    )
    for route in sorted(
        (
            item
            for item in routes
            if item.get("strategy") in {"http_tls_split", "xhttp_tls_split", "binary_tls_split"}
        ),
        key=lambda item: int(item["inbound_id"]),
    ):
        inbound_id = int(route["inbound_id"])
        strategy = str(route["strategy"])
        host = _backend_host(route["internal_host"])
        port = int(route["internal_port"])
        sni = str(route["domain"])
        options = f"ssl verify none sni str({sni})"
        alpns = [str(value) for value in route.get("alpn") or [] if value]
        if alpns:
            options += " alpn " + ",".join(alpns)
        if strategy in {"http_tls_split", "xhttp_tls_split"}:
            path = _safe_http_path(route.get("transport_path"), inbound_id)
            hosts = list(route.get("transport_hosts") or [route["domain"]])
            if not hosts:
                hosts = [route["domain"]]
            transport = str(route.get("transport") or "")
            protocol_conditions = [
                f"protocol_path_{inbound_id}",
                f"protocol_host_{inbound_id}",
            ]
            protocol_acls: list[str] = []
            if transport in {"ws", "httpupgrade"}:
                protocol_acls.extend(
                    [
                        f"    acl protocol_connection_{inbound_id} hdr(Connection) -m sub -i upgrade",
                        f"    acl protocol_upgrade_{inbound_id} hdr(Upgrade) -m found",
                    ]
                )
                protocol_conditions.extend(
                    [
                        f"protocol_connection_{inbound_id}",
                        f"protocol_upgrade_{inbound_id}",
                    ]
                )
            elif transport == "grpc":
                protocol_acls.append(
                    f"    acl protocol_grpc_{inbound_id} req.hdr(content-type) -m beg -i application/grpc"
                )
                protocol_conditions.append(f"protocol_grpc_{inbound_id}")
            elif transport == "xhttp":
                if path == "/":
                    raise ValueError(
                        f"XHTTP inbound #{inbound_id} needs a dedicated non-root path"
                    )
            else:
                raise ValueError(
                    f"HTTP transport {transport or 'unknown'} has no unambiguous browser/VPN matcher"
                )
            lines.extend(
                [
                    "",
                    f"frontend lucx_split_{inbound_id}",
                    f"    bind 127.0.0.1:{split_ports[inbound_id]} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode http",
                    *(
                        [
                            f"    acl protocol_path_{inbound_id} path -i {path}",
                            f"    acl protocol_path_{inbound_id} path_beg -i {path.rstrip('/')}/",
                        ]
                        if transport == "xhttp"
                        else [f"    acl protocol_path_{inbound_id} path_beg -i {path}"]
                    ),
                    f"    acl protocol_host_{inbound_id} hdr(host) -i "
                    + " ".join(str(value) for value in hosts),
                    *protocol_acls,
                    f"    use_backend be_http_reencrypt_{inbound_id} if "
                    + " ".join(protocol_conditions),
                    "    default_backend be_decoy_h2c_http",
                ]
            )
            if transport == "grpc":
                options += " proto h2"
            backend(f"be_http_reencrypt_{inbound_id}", host, port, options, "http")
        else:
            lines.extend(
                [
                    "",
                    f"frontend lucx_split_{inbound_id}",
                    f"    bind 127.0.0.1:{split_ports[inbound_id]} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode tcp",
                    "    tcp-request inspect-delay 5s",
                    *[
                        f"    acl is_http1 req.payload(0,16),hex -m beg {prefix}"
                        for prefix in http1_prefixes
                    ],
                    f"    acl is_http2 req.payload(0,24),hex -m str {h2_preface}",
                    "    tcp-request content accept if is_http1",
                    "    tcp-request content accept if is_http2",
                    "    use_backend be_decoy_h2c if is_http1",
                    "    use_backend be_decoy_h2c if is_http2",
                    f"    default_backend be_reencrypt_{inbound_id}",
                ]
            )
            backend(f"be_reencrypt_{inbound_id}", host, port, options)

    for name, (host, port, options, mode) in backends.items():
        lines.extend(["", f"backend {name}", f"    mode {mode}"])
        suffix = f" {options}" if options else ""
        lines.append(f"    server local {host}:{port}{suffix}")
    return "\n".join(lines) + "\n"


def render_haproxy(
    manifest: dict[str, Any],
    routing_material: dict[int | str, dict[str, Any]] | None = None,
) -> str:
    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        return _render_haproxy_extended(manifest, routing_material)
    return _render_haproxy_strict(manifest)


def render_nginx_decoys(manifest: dict[str, Any]) -> str:
    decoys = manifest["decoys"]
    cert = manifest["certificates"]["cert_path"]
    key = manifest["certificates"]["key_path"]
    listen_host = decoys["listen_host"]
    listen_port = int(decoys["listen_port"])
    extended = str(decoys.get("routing_mode") or "strict") == "extended"
    plain_listen_port = listen_port + 2
    h2c_listen = (
        f"    listen {listen_host}:{listen_port + 1} http2;" if extended else ""
    )
    lines = ["# Managed by lucx-post-configurator. Naive Caddyfile is intentionally unrelated."]
    if decoys.get("default_server"):
        lines.extend(
            [
                "server {",
                f"    listen {listen_host}:{listen_port} ssl default_server;",
                *([h2c_listen] if h2c_listen else []),
                "    server_name _;",
                f"    ssl_certificate {cert};",
                f"    ssl_certificate_key {key};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    return 404;",
                "}",
                "",
            ]
        )
    for site in decoys.get("sites", []):
        lines.extend(
            [
                "server {",
                f"    listen {listen_host}:{listen_port} ssl;",
                *([f"    listen {listen_host}:{plain_listen_port};"] if extended else []),
                *([h2c_listen] if h2c_listen else []),
                f"    server_name {site['domain']};",
                f"    ssl_certificate {cert};",
                f"    ssl_certificate_key {key};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    server_tokens off;",
                f'    add_header X-LucX-Decoy "{site["domain"]}" always;',
                f"    root {site['root']};",
                "    index index.html;",
                "    location / { try_files $uri $uri/ /index.html =404; }",
                "}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_decoy_index(domain: str) -> str:
    safe_domain = domain.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Service available</title>
  <style>body{{font:16px system-ui,sans-serif;max-width:44rem;margin:12vh auto;padding:2rem;color:#27313a}}main{{border:1px solid #d9e0e6;border-radius:12px;padding:2rem}}h1{{font-size:1.5rem}}</style>
</head>
<body><main><h1>Service available</h1><p>{safe_domain}</p></main></body>
</html>
"""


def _protected_trusttunnel_ports(manifest: dict[str, Any]) -> set[int]:
    """Return listeners proven to be reachable through the managed shared TCP port."""

    decoys = manifest.get("decoys") or {}
    if str(decoys.get("routing_mode") or "strict") != "extended":
        return set()
    public_tcp_port = int((manifest.get("network") or {}).get("public_tcp_port") or 443)
    protocols = {
        int(item.get("inbound_id") or 0): item
        for item in manifest.get("protocols") or []
        if isinstance(item, dict)
        and str(item.get("protocol") or "").strip().lower()
        in {"trusttunnel", "trust-tunnel"}
    }
    protected: set[int] = set()
    for route in decoys.get("extended_routes") or []:
        if not isinstance(route, dict):
            continue
        if (
            str(route.get("strategy") or "") != "trusttunnel_clienthello_split"
            or str(route.get("status") or "") != "ready"
            or route.get("managed") is not True
            or int(route.get("public_tcp_port") or 0) != public_tcp_port
        ):
            continue
        protocol = protocols.get(int(route.get("inbound_id") or 0))
        if not protocol or str(protocol.get("exposure") or "") != "tcp_sni":
            continue
        if int(protocol.get("public_port") or 0) != public_tcp_port:
            continue
        internal_port = int(protocol.get("internal_port") or 0)
        if internal_port != int(route.get("internal_port") or 0):
            continue
        if 1 <= internal_port <= 65535 and internal_port != public_tcp_port:
            protected.add(internal_port)
    return protected


def render_nftables(manifest: dict[str, Any]) -> str:
    internal_tcp = {
        int(manifest["lucx"]["panel"]["internal_port"]),
        int(manifest["lucx"]["subscription"]["internal_port"]),
    }
    if manifest["decoys"].get("enabled"):
        internal_tcp.add(int(manifest["decoys"]["listen_port"]))
        if str(manifest["decoys"].get("routing_mode") or "strict") == "extended":
            internal_tcp.add(int(manifest["decoys"]["listen_port"]) + 1)
            routes = list(manifest["decoys"].get("extended_routes") or [])
            internal_tcp.update(extended_split_ports(manifest, routes).values())
    if manifest["components"].get("sidecar"):
        internal_tcp.add(int(manifest["sidecar"]["listen_port"]))
    ports = ", ".join(str(port) for port in sorted(internal_tcp))
    protected_trusttunnel = _protected_trusttunnel_ports(manifest)
    trusttunnel_rules = ""
    if protected_trusttunnel:
        trust_ports = ", ".join(str(port) for port in sorted(protected_trusttunnel))
        trusttunnel_rules = (
            f'        iifname != "lo" tcp dport {{ {trust_ports} }} counter drop comment "TrustTunnel internal TCP"\n'
            f'        iifname != "lo" udp dport {{ {trust_ports} }} counter drop comment "TrustTunnel internal UDP"\n'
        )
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    cloudflare_sets = ""
    cloudflare_rules = ""
    if cloudflare_only:
        from .cloudflare import validate_networks

        stored = (manifest.get("cloudflare") or {}).get("networks") or {}
        networks = validate_networks(
            list(stored.get("ipv4") or []) + list(stored.get("ipv6") or [])
        )
        ipv4 = ", ".join(networks["ipv4"])
        ipv6 = ", ".join(networks["ipv6"])
        protected = ", ".join(
            str(port)
            for port in sorted(
                {
                    int(manifest["lucx"]["panel"]["internal_port"]),
                    int(manifest["lucx"]["subscription"]["internal_port"]),
                }
            )
        )
        cloudflare_sets = f"""    set cloudflare4 {{
        type ipv4_addr
        flags interval
        elements = {{ {ipv4} }}
    }}

    set cloudflare6 {{
        type ipv6_addr
        flags interval
        elements = {{ {ipv6} }}
    }}

"""
        cloudflare_rules = (
            f'        ip saddr @cloudflare4 tcp dport {{ {protected} }} counter accept comment "Cloudflare origin IPv4"\n'
            f'        ip6 saddr @cloudflare6 tcp dport {{ {protected} }} counter accept comment "Cloudflare origin IPv6"\n'
        )
    if manifest.get("firewall", {}).get("mode") != "strict_allowlist":
        return f"""# Managed by lucx-post-configurator. This file never flushes the host ruleset.
table inet lucx_post {{
{cloudflare_sets}
    chain protect_internal {{
        type filter hook input priority -5; policy accept;
{cloudflare_rules}
        iifname != "lo" tcp dport {{ {ports} }} counter drop comment "LucX internal listeners"
{trusttunnel_rules}
    }}
}}
"""

    allowed_tcp: set[str] = {
        str(int(manifest["lucx"]["panel"].get("public_port", manifest["network"]["public_tcp_port"]))),
        str(int(manifest["lucx"]["subscription"].get("public_port", manifest["network"]["public_tcp_port"]))),
    }
    if manifest["decoys"].get("enabled"):
        allowed_tcp.add(str(int(manifest["network"]["public_tcp_port"])))
    allowed_tcp.update(
        str(int(port))
        for port in (manifest["network"].get("ssh_ports") or [manifest["network"]["ssh_port"]])
    )
    allowed_udp: set[str] = set()
    for protocol in manifest.get("protocols", []):
        exposure = protocol.get("exposure")
        if exposure == "none":
            continue
        protected_trusttunnel_listener = (
            str(protocol.get("protocol") or "").strip().lower()
            in {"trusttunnel", "trust-tunnel"}
            and int(protocol.get("internal_port") or 0) in protected_trusttunnel
        )
        public = str(int(protocol["public_port"]))
        if exposure in {"tcp_sni", "tcp_direct", "tcp_udp_direct"}:
            allowed_tcp.add(public)
        if not protected_trusttunnel_listener and (
            exposure in {"udp_direct", "tcp_udp_direct"} or (
            exposure == "tcp_sni" and protocol.get("network") == "both"
            )
        ):
            allowed_udp.add(
                str(
                    int(
                        protocol.get("udp_public_port", protocol.get("internal_port"))
                        if exposure == "tcp_sni"
                        else protocol["public_port"]
                    )
                )
            )
        for binding in protocol.get("port_bindings") or []:
            value = str(binding.get("port") or binding.get("port_range"))
            transport = str(binding.get("protocol") or "").upper()
            if exposure in {"tcp_direct", "tcp_udp_direct"} and transport in {"TCP", "TCP_UDP"}:
                allowed_tcp.add(value)
            if (
                not protected_trusttunnel_listener
                and exposure in {"udp_direct", "tcp_udp_direct", "tcp_sni"}
                and transport in {"UDP", "TCP_UDP"}
            ):
                allowed_udp.add(value)

    def sort_ports(values: set[str]) -> list[str]:
        return sorted(values, key=lambda value: int(value.split("-", 1)[0]))

    tcp_set = ", ".join(sort_ports(allowed_tcp))
    allowed_udp.update({"68", "546"})
    udp_rule = ""
    if allowed_udp:
        udp_set = ", ".join(sort_ports(allowed_udp))
        udp_rule = f'        udp dport {{ {udp_set} }} counter accept comment "LucX public UDP"\n'
    return f"""# Managed by lucx-post-configurator. This file never flushes the host ruleset.
table inet lucx_post {{
{cloudflare_sets}
    chain strict_input {{
        type filter hook input priority 5; policy drop;
        ct state established,related counter accept
        iifname "lo" counter accept
        ip protocol icmp counter accept
        ip6 nexthdr ipv6-icmp counter accept
{cloudflare_rules}
        tcp dport {{ {tcp_set} }} counter accept comment "SSH and LucX public TCP"
{udp_rule}    }}
}}
"""


def render_firewall_unit() -> str:
    return """[Unit]
Description=LucX post-configurator isolated firewall table
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet lucx_post
ExecStart=/usr/sbin/nft -f /etc/nftables.d/60-lucx-post-configurator.nft
ExecStop=-/usr/sbin/nft delete table inet lucx_post

[Install]
WantedBy=multi-user.target
"""


def render_resolvconf(servers: list[str], existing: str = "") -> str:
    preserved = []
    for line in existing.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("nameserver ") or stripped == "# managed by lucx-post-configurator":
            continue
        if line.strip():
            preserved.append(line)
    result = "# Managed by lucx-post-configurator\n" + "".join(
        f"nameserver {server}\n" for server in servers
    )
    if preserved:
        result += "\n".join(preserved) + "\n"
    return result


def render_resolved(servers: list[str]) -> str:
    return "[Resolve]\nDNS=" + " ".join(servers) + "\nFallbackDNS=\n"


def render_logrotate() -> str:
    return """/var/log/x-ui/*.log {
    daily
    maxsize 10M
    rotate 14
    maxage 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}

/var/log/lucx-sub-sidecar/*.log {
    daily
    maxsize 5M
    rotate 7
    maxage 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
"""


def render_cloudflare_acl(manifest: dict[str, Any]) -> str:
    from .cloudflare import validate_networks

    networks = (manifest.get("cloudflare") or {}).get("networks") or {}
    validated = validate_networks(
        list(networks.get("ipv4") or []) + list(networks.get("ipv6") or [])
    )
    return "\n".join(validated["ipv4"] + validated["ipv6"]) + "\n"


def render_cloudflare_update_unit() -> str:
    return """[Unit]
Description=Refresh official Cloudflare origin networks for LucX
Wants=network-online.target
After=network-online.target haproxy.service
ConditionPathExists=/etc/haproxy/haproxy.cfg

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/lucx-cloudflare-ips-update
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/haproxy /run/lock
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
"""


def render_cloudflare_update_timer() -> str:
    return """[Unit]
Description=Daily Cloudflare origin network refresh for LucX

[Timer]
OnBootSec=15min
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
Unit=lucx-cloudflare-ips-update.service

[Install]
WantedBy=timers.target
"""


def render_sidecar_env(manifest: dict[str, Any]) -> str:
    sidecar = manifest["sidecar"]
    certs = manifest["certificates"]
    values = {
        "SIDECAR_LISTEN_HOST": sidecar["listen_host"],
        "SIDECAR_LISTEN_PORT": sidecar["listen_port"],
        "XUI_SUB_HOST": sidecar["upstream_host"],
        "XUI_SUB_PORT": sidecar["upstream_port"],
        "XUI_SUB_SCHEME": sidecar["upstream_scheme"],
        "XUI_DB": manifest["lucx"]["db_path"],
        "SIDECAR_CERT": certs["cert_path"],
        "SIDECAR_KEY": certs["key_path"],
        "SIDECAR_ALLOWED_HOSTS": ",".join(sidecar["allowed_hosts"]),
        "SIDECAR_ALLOWED_PATH_PREFIXES": ",".join(sidecar["allowed_path_prefixes"]),
        "XUI_AWG_PATH": sidecar["awg_path"],
    }
    for value in values.values():
        if "\n" in str(value) or "\r" in str(value):
            raise ValueError("newline in sidecar environment")
    return "".join(f'{key}="{str(value).replace(chr(34), chr(92) + chr(34))}"\n' for key, value in values.items())


def render_sidecar_unit() -> str:
    return """[Unit]
Description=LucX subscription compatibility sidecar
After=network.target x-ui.service
Requires=x-ui.service

[Service]
Type=simple
User=root
Group=root
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/etc/lucx-sub-sidecar/env
ExecStart=/usr/bin/python3 /usr/local/libexec/lucx-sub-sidecar.py
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
SystemCallArchitectures=native
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
"""


def render_tls_hook(manifest: dict[str, Any]) -> str:
    services = ["x-ui"]
    if manifest["components"].get("haproxy"):
        services.append("haproxy")
    if manifest["components"].get("nginx"):
        services.append("nginx")
    if manifest["components"].get("sidecar"):
        services.append("lucx-sub-sidecar")
    service_words = " ".join(services)
    required_domains = {
        manifest["lucx"]["panel"]["domain"],
        manifest["lucx"]["subscription"]["domain"],
    }
    if manifest["decoys"].get("enabled"):
        required_domains.update(site["domain"] for site in manifest["decoys"].get("sites", []))
    domain_words = " ".join(shlex.quote(domain) for domain in sorted(required_domains))
    return f"""#!/bin/sh
set -eu

CERT={shlex.quote(manifest['certificates']['cert_path'])}
KEY={shlex.quote(manifest['certificates']['key_path'])}

test -s "$CERT"
test -s "$KEY"
openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null

LUCX_TLS_TMP=$(mktemp -d "${{TMPDIR:-/tmp}}/lucx-tls-reload.XXXXXX")
cleanup() {{ rm -rf -- "$LUCX_TLS_TMP"; }}
trap cleanup EXIT HUP INT TERM
openssl x509 -in "$CERT" -pubkey -noout >"$LUCX_TLS_TMP/cert.pub"
openssl pkey -in "$KEY" -pubout >"$LUCX_TLS_TMP/key.pub"
cmp -s "$LUCX_TLS_TMP/cert.pub" "$LUCX_TLS_TMP/key.pub"

python3 - "$CERT" {domain_words} <<'PY'
import ssl
import sys

certificate = ssl._ssl._test_decode_cert(sys.argv[1])
patterns = [value.lower().rstrip(".") for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"]

def covers(pattern, hostname):
    hostname = hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        return hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count(".")
    return pattern == hostname

missing = [hostname for hostname in sys.argv[2:] if not any(covers(pattern, hostname) for pattern in patterns)]
if missing:
    raise SystemExit("renewed certificate does not cover: " + ", ".join(missing))
PY

if command -v haproxy >/dev/null 2>&1 && systemctl is-enabled haproxy.service >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
fi
if command -v nginx >/dev/null 2>&1 && systemctl is-enabled nginx.service >/dev/null 2>&1; then
    nginx -t >/dev/null
fi

for service in {service_words}; do
    if systemctl is-enabled "$service.service" >/dev/null 2>&1 || systemctl is-active "$service.service" >/dev/null 2>&1; then
        systemctl try-reload-or-restart "$service.service"
    fi
done
"""


def render_managed_naive_files(
    manifest: dict[str, Any],
    routing_material: dict[int | str, dict[str, Any]] | None,
) -> dict[str, GeneratedFile]:
    from .naive_frontend import (
        parse_naive_caddyfile,
        render_managed_naive_caddyfile,
        render_naive_frontend_unit,
    )

    result: dict[str, GeneratedFile] = {}
    routes = [
        item
        for item in (manifest.get("decoys") or {}).get("extended_routes") or []
        if item.get("strategy") == "naive_managed" and item.get("status") == "ready"
    ]
    if not routes:
        return result
    if not (manifest.get("components") or {}).get("naive_frontend"):
        raise ValueError("managed Naive route requires components.naive_frontend")
    sites = {
        str(item.get("domain") or "").lower(): str(item.get("root") or "")
        for item in (manifest.get("decoys") or {}).get("sites") or []
    }
    for route in routes:
        inbound_id = int(route["inbound_id"])
        material = (routing_material or {}).get(inbound_id) or (routing_material or {}).get(
            str(inbound_id)
        )
        if not isinstance(material, dict):
            raise ValueError(f"Naive inbound #{inbound_id} ephemeral source is unavailable")
        source = material.get("naive_caddyfile_text")
        if not isinstance(source, str):
            raise ValueError(f"Naive inbound #{inbound_id} ephemeral source is unavailable")
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if digest != str(route.get("source_caddyfile_sha256") or ""):
            raise ValueError(f"Naive inbound #{inbound_id} source changed after planning")
        parsed = parse_naive_caddyfile(source)
        domain = str(route["domain"]).lower()
        site_root = sites.get(domain, f"/var/www/lucx-decoys/{domain}")
        if not site_root:
            raise ValueError(f"Naive inbound #{inbound_id} has no managed decoy root")
        binary_path = str(route.get("binary_path") or "")
        config_path = f"/etc/lucx-post-configurator/naive/naive-{inbound_id}.caddyfile"
        unit_path = f"/etc/systemd/system/lucx-naive-decoy-{inbound_id}.service"
        result[config_path] = GeneratedFile(
            render_managed_naive_caddyfile(
                parsed,
                domain=domain,
                listen_port=int(route["managed_listen_port"]),
                cert_path=str(manifest["certificates"]["cert_path"]),
                key_path=str(manifest["certificates"]["key_path"]),
                site_root=site_root,
            ).encode(),
            mode=0o600,
            component="naive_frontend",
        )
        result[unit_path] = GeneratedFile(
            render_naive_frontend_unit(inbound_id=inbound_id, binary_path=binary_path).encode(),
            component="naive_frontend",
        )
    return result


def render_files(
    manifest: dict[str, Any],
    resolver: str = "auto",
    existing_dns_text: str = "",
    routing_material: dict[int | str, dict[str, Any]] | None = None,
) -> dict[str, GeneratedFile]:
    validate_manifest(manifest)
    components = manifest["components"]
    result: dict[str, GeneratedFile] = {}
    if components.get("trusttunnel_backend"):
        from .trusttunnel_backend import (
            render_backend_credentials_toml,
            render_backend_hosts_toml,
            render_backend_rules_toml,
            render_backend_unit,
            render_backend_vpn_toml,
        )

        result["/etc/x-tuna/trusttunnel/vpn.toml"] = GeneratedFile(
            render_backend_vpn_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/hosts.toml"] = GeneratedFile(
            render_backend_hosts_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/rules.toml"] = GeneratedFile(
            render_backend_rules_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/credentials.toml"] = GeneratedFile(
            render_backend_credentials_toml(manifest), mode=0o600, component="trusttunnel_backend"
        )
        result["/etc/systemd/system/x-tuna-trusttunnel-backend.service"] = GeneratedFile(
            render_backend_unit(manifest), mode=0o644, component="trusttunnel_backend"
        )
    if components.get("haproxy"):
        result["/etc/haproxy/haproxy.cfg"] = GeneratedFile(
            render_haproxy(manifest, routing_material=routing_material).encode(),
            component="haproxy",
        )
        if (
            str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended"
            and components.get("extended_tls_split")
        ):
            result["/etc/lucx-post-configurator/tls/certificate.pem"] = GeneratedFile(
                mode=0o640,
                component="haproxy",
                symlink_target=str(manifest["certificates"]["cert_path"]),
            )
            result["/etc/lucx-post-configurator/tls/certificate.pem.key"] = GeneratedFile(
                mode=0o640,
                component="haproxy",
                symlink_target=str(manifest["certificates"]["key_path"]),
            )
    if (manifest.get("cloudflare") or {}).get("enabled"):
        updater_source = importlib.resources.files("lucx_post_configurator").joinpath(
            "assets/cloudflare_ips_update.py"
        ).read_bytes()
        result["/etc/haproxy/cloudflare-ips.lst"] = GeneratedFile(
            render_cloudflare_acl(manifest).encode(), component="cloudflare"
        )
        result["/usr/local/sbin/lucx-cloudflare-ips-update"] = GeneratedFile(
            updater_source, mode=0o755, component="cloudflare"
        )
        result["/etc/systemd/system/lucx-cloudflare-ips-update.service"] = GeneratedFile(
            render_cloudflare_update_unit().encode(), component="cloudflare"
        )
        result["/etc/systemd/system/lucx-cloudflare-ips-update.timer"] = GeneratedFile(
            render_cloudflare_update_timer().encode(), component="cloudflare"
        )
    if components.get("nginx") and manifest["decoys"].get("enabled"):
        result["/etc/nginx/conf.d/60-lucx-decoys.conf"] = GeneratedFile(
            render_nginx_decoys(manifest).encode(), component="nginx"
        )
        if manifest["decoys"].get("create_content"):
            for site in manifest["decoys"].get("sites", []):
                result[site["root"] + "/index.html"] = GeneratedFile(
                    render_decoy_index(site["domain"]).encode(), component="nginx"
                )
    if components.get("naive_frontend"):
        result.update(render_managed_naive_files(manifest, routing_material))
    if manifest["dns"].get("enabled"):
        servers = manifest["dns"]["servers"]
        if resolver in {"auto", "resolvconf"}:
            result["/etc/resolvconf/resolv.conf.d/head"] = GeneratedFile(
                render_resolvconf(servers, existing_dns_text).encode(), component="dns"
            )
        if resolver == "systemd-resolved":
            result["/etc/systemd/resolved.conf.d/60-lucx-post-configurator.conf"] = GeneratedFile(
                render_resolved(servers).encode(), component="dns"
            )
        if resolver == "static":
            result["/etc/resolv.conf"] = GeneratedFile(
                render_resolvconf(servers, existing_dns_text).encode(), component="dns"
            )
    if components.get("firewall"):
        result["/etc/nftables.d/60-lucx-post-configurator.nft"] = GeneratedFile(
            render_nftables(manifest).encode(), component="firewall"
        )
        result["/etc/systemd/system/lucx-post-firewall.service"] = GeneratedFile(
            render_firewall_unit().encode(), component="firewall"
        )
    if components.get("logrotate"):
        result["/etc/logrotate.d/lucx-x-ui"] = GeneratedFile(render_logrotate().encode(), component="logrotate")
    if components.get("sidecar"):
        sidecar_source = importlib.resources.files("lucx_post_configurator").joinpath("assets/lucx_sub_sidecar.py").read_bytes()
        result["/usr/local/libexec/lucx-sub-sidecar.py"] = GeneratedFile(sidecar_source, mode=0o755, component="sidecar")
        result["/etc/lucx-sub-sidecar/env"] = GeneratedFile(
            render_sidecar_env(manifest).encode(), mode=0o600, component="sidecar"
        )
        result["/etc/systemd/system/lucx-sub-sidecar.service"] = GeneratedFile(
            render_sidecar_unit().encode(), component="sidecar"
        )
    if components.get("tls_hook"):
        hook = render_tls_hook(manifest).encode()
        result["/usr/local/sbin/lucx-tls-reload"] = GeneratedFile(hook, mode=0o750, component="certificates")
        result["/etc/letsencrypt/renewal-hooks/deploy/60-lucx-post-configurator"] = GeneratedFile(
            b"#!/bin/sh\nexec /usr/local/sbin/lucx-tls-reload\n", mode=0o750, component="certificates"
        )
    return result
