from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Audit, valid_domain
from .extended_decoys import classify_extended_decoy_routes


MANAGED_STATUSES = {
    "direct_tcp_decoy",
    "udp_with_tcp_decoy",
    "reality_endpoint_decoy",
    "extended_ready",
}

CAPABILITY_STATUSES = MANAGED_STATUSES | {
    "existing_fallback_observed",
    "naive_caddy_owned_readonly",
    "blocked_sni_collision",
    "unsupported_safe",
    "extended_ready",
    "extended_blocked",
}

KNOWN_EXPOSURES = {"tcp_sni", "tcp_direct", "udp_direct", "tcp_udp_direct", "none"}
KNOWN_NETWORKS = {"tcp", "udp", "both"}


def _domain(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _port(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _network(item: dict[str, Any]) -> str:
    value = str(item.get("network") or "").lower()
    if value:
        return value
    exposure = str(item.get("exposure") or "")
    if exposure == "udp_direct":
        return "udp"
    if exposure == "tcp_udp_direct":
        return "both"
    if exposure in {"tcp_sni", "tcp_direct", "none"}:
        return "tcp"
    return ""


def _existing_observations(manifest: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for item in (manifest.get("decoys") or {}).get("capabilities") or []:
        probe = item.get("probe") or {}
        if (
            item.get("status") == "existing_fallback_observed"
            and probe.get("state") == "site_observed"
        ):
            domain = _domain(item.get("domain"))
            if domain:
                result.add(domain)
    return result


def _record(
    domain: str,
    protocols: list[dict[str, Any]],
    status: str,
    reason: str,
    evidence: list[str],
) -> dict[str, Any]:
    managed = status in MANAGED_STATUSES
    return {
        "domain": domain,
        "status": status,
        "managed": managed,
        "protocol_ids": sorted(
            int(item.get("inbound_id") or 0)
            for item in protocols
            if int(item.get("inbound_id") or 0) > 0
        ),
        "evidence": list(dict.fromkeys(evidence)),
        "reason": reason,
        "probe_mode": "active" if managed else "passive" if status in {
            "existing_fallback_observed",
            "naive_caddy_owned_readonly",
            "blocked_sni_collision",
        } else "none",
    }


def classify_decoy_capabilities(
    manifest: dict[str, Any],
    audit: Audit | None = None,
) -> list[dict[str, Any]]:
    """Classify browser-site coverage without changing a protocol topology."""

    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        configured = list((manifest.get("decoys") or {}).get("extended_routes") or [])
        routes = configured or classify_extended_decoy_routes(manifest, audit)
        grouped_routes: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for route in routes:
            domain = _domain(route.get("domain"))
            if domain and valid_domain(domain):
                grouped_routes[domain].append(route)
        extended_records: list[dict[str, Any]] = []
        for domain in sorted(grouped_routes):
            domain_routes = grouped_routes[domain]
            ready = all(str(item.get("status") or "blocked") == "ready" for item in domain_routes)
            strategies = list(
                dict.fromkeys(str(item.get("strategy") or "blocked_unknown") for item in domain_routes)
            )
            evidence: list[str] = []
            for item in domain_routes:
                evidence.extend(str(value) for value in item.get("evidence") or [])
            reasons = [str(item.get("reason") or "") for item in domain_routes]
            extended_records.append(
                {
                    "domain": domain,
                    "status": "extended_ready" if ready else "extended_blocked",
                    "managed": ready,
                    "strategy": ",".join(strategies),
                    "protocol_ids": sorted(
                        {
                            _port(item.get("inbound_id"))
                            for item in domain_routes
                            if _port(item.get("inbound_id")) > 0
                        }
                    ),
                    "evidence": list(dict.fromkeys(evidence)),
                    "reason": "; ".join(dict.fromkeys(reason for reason in reasons if reason)),
                    "probe_mode": "active" if ready else "none",
                    "tls_termination": any(bool(item.get("tls_termination")) for item in domain_routes),
                    "preflight_required": any(bool(item.get("preflight_required")) for item in domain_routes),
                }
            )
        return extended_records

    shared_port = _port((manifest.get("network") or {}).get("public_tcp_port"))
    observed = _existing_observations(manifest)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for protocol in manifest.get("protocols") or []:
        domain = _domain(protocol.get("domain"))
        if domain and valid_domain(domain):
            grouped[domain].append(protocol)

    # The DNS zone apex (for example "lesovoi.store") is not owned by any
    # protocol listener: HAProxy routes it as a standalone Nginx decoy site.
    # Classify it explicitly so validation, health probes and the TUI treat it
    # as a managed direct site instead of ignoring it.
    panel_domain = _domain(
        (manifest.get("lucx") or {}).get("panel", {}).get("domain")
    )
    if panel_domain and "." in panel_domain:
        apex = panel_domain.split(".", 1)[1]
        if valid_domain(apex) and apex not in grouped:
            grouped[apex] = []

    records: list[dict[str, Any]] = []
    for domain in sorted(grouped):
        protocols = grouped[domain]
        evidence = [
            "inbound #{} {} network={} exposure={} public_port={}".format(
                int(item.get("inbound_id") or 0),
                str(item.get("protocol") or "unknown"),
                _network(item) or "unknown",
                str(item.get("exposure") or "unknown"),
                _port(item.get("public_port")),
            )
            for item in protocols
        ]

        if any(
            item.get("exposure") not in KNOWN_EXPOSURES
            or _network(item) not in KNOWN_NETWORKS
            for item in protocols
        ):
            records.append(
                _record(
                    domain,
                    protocols,
                    "unsupported_safe",
                    "Транспорт или способ публикации не доказан; автоматический маршрут запрещён.",
                    evidence,
                )
            )
            continue

        sni_owners: list[dict[str, Any]] = []
        for item in protocols:
            if item.get("exposure") != "tcp_sni" or _port(item.get("public_port")) != shared_port:
                continue
            names = [_domain(value) for value in item.get("sni_names") or []]
            if not names:
                names = [_domain(item.get("domain"))]
            if domain in names:
                sni_owners.append(item)
                evidence.append(
                    f"inbound #{int(item.get('inbound_id') or 0)} owns ClientHello SNI {domain} on TCP/{shared_port}"
                )

        if sni_owners:
            if any(str(item.get("protocol") or "").lower() == "naive" for item in sni_owners):
                caddy_found = bool(audit and audit.naive_caddyfile.get("found"))
                evidence.append(f"Naive Caddyfile found={str(caddy_found).lower()}")
                records.append(
                    _record(
                        domain,
                        protocols,
                        "naive_caddy_owned_readonly",
                        "SNI принадлежит Naive; Caddyfile доступен только для чтения.",
                        evidence,
                    )
                )
            elif domain in observed:
                records.append(
                    _record(
                        domain,
                        protocols,
                        "existing_fallback_observed",
                        "Обычный HTTPS-сайт ранее подтверждён через существующий protocol fallback.",
                        evidence,
                    )
                )
            else:
                records.append(
                    _record(
                        domain,
                        protocols,
                        "blocked_sni_collision",
                        f"Протокол уже владеет тем же SNI на TCP/{shared_port}; VPN имеет приоритет.",
                        evidence,
                    )
                )
            continue

        direct_public_tcp = [
            item
            for item in protocols
            if item.get("exposure") in {"tcp_direct", "tcp_udp_direct"}
            and _port(item.get("public_port")) == shared_port
        ]
        if direct_public_tcp:
            evidence.append(f"direct protocol listener owns TCP/{shared_port}")
            records.append(
                _record(
                    domain,
                    protocols,
                    "blocked_sni_collision",
                    f"Прямой protocol listener уже занимает TCP/{shared_port}; внешний перехват запрещён.",
                    evidence,
                )
            )
            continue

        reality_endpoint = any(
            item.get("exposure") == "tcp_sni"
            and item.get("security") == "reality"
            and _port(item.get("public_port")) == shared_port
            and domain not in {_domain(value) for value in item.get("sni_names") or []}
            for item in protocols
        )
        if reality_endpoint:
            records.append(
                _record(
                    domain,
                    protocols,
                    "reality_endpoint_decoy",
                    "Endpoint-домен отличается от Reality camouflage SNI; браузерный SNI свободен.",
                    evidence,
                )
            )
            continue

        if protocols and all(_network(item) == "udp" for item in protocols):
            records.append(
                _record(
                    domain,
                    protocols,
                    "udp_with_tcp_decoy",
                    "VPN использует UDP; независимый браузерный TCP listener не меняет протокол.",
                    evidence,
                )
            )
            continue

        records.append(
            _record(
                domain,
                protocols,
                "direct_tcp_decoy",
                f"Для домена не найден владелец protocol SNI или listener на TCP/{shared_port}.",
                evidence,
            )
        )

    return records


def managed_decoy_domains(manifest: dict[str, Any]) -> list[str]:
    capabilities = list((manifest.get("decoys") or {}).get("capabilities") or [])
    if not capabilities:
        capabilities = classify_decoy_capabilities(manifest)
    return sorted(
        {
            _domain(item.get("domain"))
            for item in capabilities
            if item.get("managed") and valid_domain(_domain(item.get("domain")))
        }
    )
