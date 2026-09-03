from __future__ import annotations

import unittest
from pathlib import Path

from lucx_post_configurator.models import ConfigurationError, default_manifest, validate_manifest
from lucx_post_configurator.validation import (
    _direct_decoy_domains,
    _managed_naive_adapt_commands,
    _managed_naive_live_requirements,
    _parse_ss_listener_ports,
    _parse_ss_tcp_listeners,
    _validate_trusttunnel_firewall_listing,
)


class ValidationTests(unittest.TestCase):
    def test_live_firewall_requires_both_trusttunnel_transport_drop_rules(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["routing_mode"] = "extended"
        manifest["protocols"] = [
            {
                "inbound_id": 9,
                "protocol": "trusttunnel",
                "internal_port": 9443,
                "public_port": 443,
                "exposure": "tcp_sni",
            }
        ]
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 9,
                "strategy": "trusttunnel_clienthello_split",
                "status": "ready",
                "managed": True,
                "internal_port": 9443,
                "public_tcp_port": 443,
            }
        ]
        tcp_only = (
            'chain protect_internal {\n'
            '  iifname != "lo" tcp dport 9443 counter drop '
            'comment "TrustTunnel internal TCP"\n'
            '}\n'
        )

        self.assertEqual(
            _validate_trusttunnel_firewall_listing(manifest, tcp_only),
            ["TrustTunnel internal UDP firewall drop is missing for port 9443"],
        )
        both = tcp_only.replace(
            "}\n",
            '  iifname != "lo" udp dport 9443 counter drop '
            'comment "TrustTunnel internal UDP"\n}\n',
        )
        self.assertEqual(_validate_trusttunnel_firewall_listing(manifest, both), [])

    def test_managed_naive_live_requirements_include_service_and_loopback_port(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 7,
                "strategy": "naive_managed",
                "status": "ready",
                "managed_listen_port": 26443,
            },
            {
                "inbound_id": 8,
                "strategy": "naive_native",
                "status": "ready",
            },
        ]

        self.assertEqual(
            _managed_naive_live_requirements(manifest),
            (["lucx-naive-decoy-7.service"], {26443}),
        )

    def test_managed_naive_frontend_is_adapted_with_its_discovered_binary(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 7,
                "strategy": "naive_managed",
                "status": "ready",
                "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
            }
        ]
        staged_path = Path("/tmp/staged-naive-7.caddyfile")
        staged = {
            "/etc/lucx-post-configurator/naive/naive-7.caddyfile": staged_path
        }

        self.assertEqual(
            _managed_naive_adapt_commands(manifest, staged),
            [
                (
                    [
                        "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                        "adapt",
                        "--config",
                        str(staged_path),
                        "--adapter",
                        "caddyfile",
                    ],
                    "managed Naive inbound #7",
                )
            ],
        )

    def test_managed_decoy_cannot_overlap_protocol_owned_sni(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.com"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.com"
        manifest["certificates"]["cert_path"] = "/cert/fullchain.pem"
        manifest["certificates"]["key_path"] = "/cert/privkey.pem"
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "trojan",
                "domain": "owned.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 10443,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "sni_names": ["owned.example.com"],
                "port_bindings": [],
            }
        ]
        manifest["decoys"].update(
            {
                "enabled": True,
                "sites": [
                    {"domain": "owned.example.com", "root": "/var/www/lucx-decoys/owned.example.com"}
                ],
                "capabilities": [
                    {
                        "domain": "owned.example.com",
                        "status": "direct_tcp_decoy",
                        "managed": True,
                        "protocol_ids": [1],
                        "evidence": [],
                        "reason": "incorrectly free",
                        "probe_mode": "active",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(ConfigurationError, "decoy route.*protocol SNI"):
            validate_manifest(manifest)

    def test_only_free_browser_sni_is_probed_as_direct_nginx_decoy(self) -> None:
        manifest = {
            "network": {"public_tcp_port": 443},
            "protocols": [
                {
                    "exposure": "tcp_sni",
                    "public_port": 443,
                    "domain": "endpoint.example.com",
                    "sni_names": ["occupied.example.com"],
                }
            ],
            "decoys": {
                "sites": [
                    {"domain": "endpoint.example.com"},
                    {"domain": "occupied.example.com"},
                ]
            },
        }
        self.assertEqual(_direct_decoy_domains(manifest), ["endpoint.example.com"])

    def test_parses_ipv4_ipv6_and_process_from_ss(self) -> None:
        output = (
            'LISTEN 0 4096 127.0.0.1:443 0.0.0.0:* users:(("caddy",pid=1,fd=7))\n'
            'LISTEN 0 128 [::]:49283 [::]:* users:(("sshd",pid=2,fd=3))\n'
        )
        self.assertEqual(
            _parse_ss_tcp_listeners(output),
            [
                ("127.0.0.1", 443, 'users:(("caddy",pid=1,fd=7))'),
                ("::", 49283, 'users:(("sshd",pid=2,fd=3))'),
            ],
        )

    def test_parses_tcp_and_udp_listener_ports(self) -> None:
        output = (
            "LISTEN 0 4096 127.0.0.1:2083 0.0.0.0:*\n"
            "UNCONN 0 0 [::]:443 [::]:*\n"
        )
        self.assertEqual(_parse_ss_listener_ports(output), {443, 2083})


if __name__ == "__main__":
    unittest.main()
