from __future__ import annotations

import unittest

from lucx_post_configurator.decoy_capabilities import (
    classify_decoy_capabilities,
    managed_decoy_domains,
)
from lucx_post_configurator.models import default_manifest


def protocol(
    inbound_id: int,
    name: str,
    domain: str,
    exposure: str,
    public_port: int,
    sni_names: list[str],
    *,
    network: str = "tcp",
    security: str = "",
) -> dict:
    return {
        "inbound_id": inbound_id,
        "protocol": name,
        "remark": f"test {name}",
        "domain": domain,
        "internal_host": "127.0.0.1",
        "internal_port": 10000 + inbound_id,
        "public_port": public_port,
        "network": network,
        "exposure": exposure,
        "security": security,
        "sni_names": sni_names,
        "port_bindings": [],
    }


class DecoyCapabilityTests(unittest.TestCase):
    def test_mixed_topology_is_classified_without_stealing_protocol_sni(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            protocol(1, "vless", "owned.example.com", "tcp_sni", 443, ["owned.example.com"]),
            protocol(2, "awg", "awg.example.com", "udp_direct", 8443, [], network="udp"),
            protocol(
                3,
                "vless",
                "endpoint.example.com",
                "tcp_sni",
                443,
                ["cover.example.com"],
                security="reality",
            ),
            protocol(4, "naive", "naive.example.com", "tcp_sni", 443, ["naive.example.com"]),
            protocol(5, "mieru", "mieru.example.com", "tcp_direct", 20100, []),
        ]

        records = {
            item["domain"]: item for item in classify_decoy_capabilities(manifest)
        }

        self.assertEqual(records["owned.example.com"]["status"], "blocked_sni_collision")
        self.assertFalse(records["owned.example.com"]["managed"])
        self.assertEqual(records["awg.example.com"]["status"], "udp_with_tcp_decoy")
        self.assertTrue(records["awg.example.com"]["managed"])
        self.assertEqual(records["endpoint.example.com"]["status"], "reality_endpoint_decoy")
        self.assertTrue(records["endpoint.example.com"]["managed"])
        self.assertEqual(records["naive.example.com"]["status"], "naive_caddy_owned_readonly")
        self.assertFalse(records["naive.example.com"]["managed"])
        self.assertEqual(records["mieru.example.com"]["status"], "direct_tcp_decoy")
        self.assertTrue(records["mieru.example.com"]["managed"])

    def test_direct_tcp_listener_on_public_443_is_never_treated_as_free(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            protocol(7, "future", "future.example.com", "tcp_direct", 443, []),
        ]

        record = classify_decoy_capabilities(manifest)[0]

        self.assertEqual(record["status"], "blocked_sni_collision")
        self.assertFalse(record["managed"])
        self.assertIn("TCP/443", record["reason"])

    def test_unknown_exposure_is_conservative(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            protocol(9, "future", "future.example.com", "new_mode", 7443, []),
        ]

        record = classify_decoy_capabilities(manifest)[0]

        self.assertEqual(record["status"], "unsupported_safe")
        self.assertFalse(record["managed"])
        self.assertEqual(record["probe_mode"], "none")

    def test_same_domain_groups_all_inbound_ids_deterministically(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            protocol(8, "mieru", "same.example.com", "tcp_direct", 20100, []),
            protocol(2, "qwdtt", "same.example.com", "tcp_udp_direct", 56000, [], network="both"),
        ]

        records = classify_decoy_capabilities(manifest)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["protocol_ids"], [2, 8])
        self.assertEqual(records[0]["status"], "direct_tcp_decoy")

    def test_observed_existing_fallback_is_retained_only_for_same_collision(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            protocol(1, "trojan", "fallback.example.com", "tcp_sni", 443, ["fallback.example.com"]),
        ]
        manifest["decoys"]["capabilities"] = [
            {
                "domain": "fallback.example.com",
                "status": "existing_fallback_observed",
                "probe": {"state": "site_observed"},
            }
        ]

        record = classify_decoy_capabilities(manifest)[0]

        self.assertEqual(record["status"], "existing_fallback_observed")
        self.assertFalse(record["managed"])
        self.assertEqual(record["probe_mode"], "passive")

    def test_extended_mode_projects_ready_and_blocked_strategies_by_domain(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["routing_mode"] = "extended"
        manifest["protocols"] = [
            {
                **protocol(31, "awg", "udp.example.net", "udp_direct", 28443, [], network="udp"),
                "transport": "udp",
                "port_bindings": [{"port": 28443, "protocol": "UDP"}],
            },
            {
                **protocol(32, "future", "blocked.example.net", "tcp_sni", 443, ["blocked.example.net"]),
                "transport": "tcp",
                "security": "tls",
            },
        ]

        records = {
            item["domain"]: item for item in classify_decoy_capabilities(manifest)
        }

        self.assertEqual(records["udp.example.net"]["status"], "extended_ready")
        self.assertEqual(records["udp.example.net"]["strategy"], "tcp_side_site")
        self.assertTrue(records["udp.example.net"]["managed"])
        self.assertEqual(records["blocked.example.net"]["status"], "extended_blocked")
        self.assertFalse(records["blocked.example.net"]["managed"])
        self.assertEqual(managed_decoy_domains(manifest), ["udp.example.net"])


if __name__ == "__main__":
    unittest.main()
