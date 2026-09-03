from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lucx_post_configurator.discovery import audit_system, redacted_audit_dict
from lucx_post_configurator.diagnostics import stable_fingerprint

from helpers import make_target


class DiscoveryTests(unittest.TestCase):
    def test_share_address_port_is_public_while_listener_port_remains_internal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE inbounds SET share_addr = 'api.example.com:443' WHERE id = 1"
            )
            connection.commit()
            connection.close()
            inbound = audit_system(root).inbounds[0]
            self.assertEqual(inbound.share_addr, "api.example.com")
            self.assertEqual(inbound.port, 54703)
            self.assertEqual(inbound.suggested_public_port, 443)

    def test_enabled_host_endpoint_has_subscription_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts(id,inbound_id,sort_order,is_disabled,address,port) VALUES (10,1,0,0,'host.example.com',8443)"
            )
            connection.execute(
                "UPDATE inbounds SET share_addr = 'legacy.example.com:443' WHERE id = 1"
            )
            connection.commit()
            connection.close()

            inbound = audit_system(root).inbounds[0]
            self.assertEqual(inbound.share_addr, "host.example.com")
            self.assertEqual(inbound.suggested_public_port, 8443)
            self.assertEqual(inbound.port, 54703)

    def test_host_sni_override_is_discovered_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, sni TEXT, override_sni_from_address INTEGER, keep_sni_blank INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (10,1,0,0,'edge.example.com',443,'ignored.example.com',1,0)"
            )
            connection.commit()
            connection.close()

            inbound = audit_system(root).inbounds[0]
            self.assertIn("edge.example.com", inbound.server_names)
            self.assertNotIn("ignored.example.com", inbound.server_names)

    def test_reads_only_safe_metadata_and_all_protocol_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            audit = audit_system(root)
            self.assertTrue(audit.supported_os)
            self.assertTrue(audit.db_schema_supported)
            self.assertEqual(audit.ssh_ports, [49283])
            self.assertEqual(len(audit.inbounds), 5)
            payload = json.dumps(redacted_audit_dict(audit))
            self.assertNotIn("must-not-leak", payload)
            mieru = next(item for item in audit.inbounds if item.protocol == "mieru")
            self.assertEqual(mieru.port_bindings, [{"port_range": "27015-27035", "protocol": "TCP"}])
            qwdtt = next(item for item in audit.inbounds if item.protocol == "qwdtt")
            self.assertIn({"port": 56001, "protocol": "UDP"}, qwdtt.port_bindings)
            self.assertIn({"port": 56003, "protocol": "UDP"}, qwdtt.port_bindings)

    def test_unknown_newer_protocol_is_discovered_without_a_fixed_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        99,
                        "trusttunnel",
                        "Trust Tunnel",
                        1,
                        "127.0.0.1",
                        9443,
                        json.dumps(
                            {
                                "domain": "trust.example.com",
                                "clientRandomPrefix": "deadbeef/ffffffff",
                            }
                        ),
                        json.dumps({"network": "tcp", "security": "tls"}),
                        "trust.example.com",
                        "custom",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            audit = audit_system(root)
            trust = next(item for item in audit.inbounds if item.id == 99)
            self.assertEqual(trust.protocol, "trusttunnel")
            self.assertEqual(trust.network, "tcp")
            self.assertEqual(trust.security, "tls")
            self.assertEqual(
                trust.clienthello_match_fingerprint,
                stable_fingerprint("deadbeef/ffffffff"),
            )
            self.assertNotIn("deadbeef", json.dumps(redacted_audit_dict(audit)))

    def test_discovers_transport_tls_and_shadowsocks_capabilities_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            61,
                            "shadowsocks",
                            "SS 2022",
                            1,
                            "127.0.0.1",
                            36133,
                            json.dumps(
                                {
                                    "method": "2022-blake3-aes-256-gcm",
                                    "network": "tcp,udp",
                                    "password": "must-not-leak",
                                }
                            ),
                            json.dumps(
                                {
                                    "network": "tcp",
                                    "security": "tls",
                                    "tlsSettings": {
                                        "serverName": "ss.edge.example.net",
                                        "alpn": ["h2", "http/1.1"],
                                    },
                                }
                            ),
                            "ss.edge.example.net:443",
                            "custom",
                        ),
                        (
                            62,
                            "vmess",
                            "HTTP upgrade",
                            1,
                            "127.0.0.1",
                            58111,
                            "{}",
                            json.dumps(
                                {
                                    "network": "httpupgrade",
                                    "security": "tls",
                                    "httpupgradeSettings": {
                                        "path": "/transport-path",
                                        "host": "upgrade.edge.example.net",
                                    },
                                    "tlsSettings": {"alpn": "h2,http/1.1"},
                                }
                            ),
                            "upgrade.edge.example.net:443",
                            "custom",
                        ),
                    ],
                )
                connection.commit()
            finally:
                connection.close()

            audit = audit_system(root)
            shadowsocks = next(item for item in audit.inbounds if item.id == 61)
            self.assertEqual(shadowsocks.network, "both")
            self.assertEqual(shadowsocks.transport, "tcp")
            self.assertTrue(shadowsocks.shadowsocks_2022)
            self.assertFalse(shadowsocks.udp_over_tcp)
            self.assertEqual(shadowsocks.alpn, ["h2", "http/1.1"])
            self.assertEqual(
                shadowsocks.port_bindings,
                [
                    {"port": 36133, "protocol": "TCP"},
                    {"port": 36133, "protocol": "UDP"},
                ],
            )

            upgrade = next(item for item in audit.inbounds if item.id == 62)
            self.assertEqual(upgrade.network, "tcp")
            self.assertEqual(upgrade.transport, "httpupgrade")
            self.assertEqual(upgrade.transport_path, "/transport-path")
            self.assertEqual(upgrade.transport_hosts, ["upgrade.edge.example.net"])
            self.assertEqual(upgrade.alpn, ["h2", "http/1.1"])

            payload = json.dumps(redacted_audit_dict(audit))
            self.assertNotIn("must-not-leak", payload)

    def test_discovers_udp_over_tcp_without_assuming_a_protocol_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        63,
                        "future-protocol",
                        "Future transport",
                        1,
                        "127.0.0.1",
                        30443,
                        json.dumps({"udpOverTcp": True}),
                        json.dumps(
                            {
                                "network": "xhttp",
                                "security": "tls",
                                "xhttpSettings": {
                                    "path": "/private-xhttp",
                                    "host": "future.edge.example.net",
                                    "mode": "packet-up",
                                },
                            }
                        ),
                        "future.edge.example.net:443",
                        "custom",
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            inbound = next(item for item in audit_system(root).inbounds if item.id == 63)
            self.assertEqual(inbound.transport, "xhttp")
            self.assertEqual(inbound.transport_path, "/private-xhttp")
            self.assertEqual(inbound.transport_hosts, ["future.edge.example.net"])
            self.assertEqual(inbound.transport_mode, "packet-up")
            self.assertTrue(inbound.udp_over_tcp)

    def test_discovers_udp_l4_for_kcp_and_quic_transports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            64,
                            "vless",
                            "KCP transport",
                            1,
                            "127.0.0.1",
                            30444,
                            "{}",
                            json.dumps({"network": "kcp", "security": "none"}),
                            "kcp.edge.example.net:30444",
                            "custom",
                        ),
                        (
                            65,
                            "vmess",
                            "Legacy QUIC transport",
                            1,
                            "127.0.0.1",
                            30445,
                            "{}",
                            json.dumps({"network": "quic", "security": "none"}),
                            "quic.edge.example.net:30445",
                            "custom",
                        ),
                    ],
                )
                connection.commit()
            finally:
                connection.close()

            discovered = {item.id: item for item in audit_system(root).inbounds}

            self.assertEqual(discovered[64].transport, "kcp")
            self.assertEqual(discovered[64].network, "udp")
            self.assertEqual(discovered[65].transport, "quic")
            self.assertEqual(discovered[65].network, "udp")

    def test_all_global_ssh_ports_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            dropins = root / "etc/ssh/sshd_config.d"
            dropins.mkdir(parents=True)
            (dropins / "additional.conf").write_text("Port 2222\n", encoding="utf-8")
            self.assertEqual(audit_system(root).ssh_ports, [49283, 2222])

    def test_discovers_every_lucx_generated_naive_caddyfile_without_editing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (7, "naive", "Naive A", 1, "", 47863, "{}", "{}", "a.example.com", "custom"),
                        (12, "naive", "Naive B", 1, "", 47864, "{}", "{}", "b.example.com", "custom"),
                    ],
                )
                connection.commit()
            finally:
                connection.close()
            tunnel = root / "usr/local/x-ui/bin/tunnel"
            tunnel.mkdir(parents=True)
            (tunnel / "naive-7.caddyfile").write_text("a.example.com {}\n", encoding="utf-8")
            (tunnel / "naive-12.caddyfile").write_text("b.example.com {}\n", encoding="utf-8")

            audit = audit_system(root)

            self.assertTrue(audit.naive_caddyfile["found"])
            self.assertEqual(
                [item["path"] for item in audit.naive_caddyfile["files"]],
                [
                    "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                    "/usr/local/x-ui/bin/tunnel/naive-12.caddyfile",
                ],
            )
            self.assertTrue(all("sha256" in item for item in audit.naive_caddyfile["files"]))
            self.assertFalse(any("not located" in warning for warning in audit.warnings))

    def test_naive_caddy_capabilities_are_detected_without_exposing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (7, "naive", "Naive", 1, "127.0.0.1", 47863, "{}", "{}", "naive.example.net", "custom"),
                )
                connection.commit()
            finally:
                connection.close()
            tunnel = root / "usr/local/x-ui/bin/tunnel"
            tunnel.mkdir(parents=True)
            (tunnel / "naive-7.caddyfile").write_text(
                "naive.example.net {\n  route {\n    forward_proxy {\n      basic_auth hidden secret\n    }\n  }\n  file_server\n}\n",
                encoding="utf-8",
            )
            binary = root / "usr/local/x-ui/bin/caddy-naive-linux-amd64"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"binary-placeholder")
            binary.chmod(0o755)

            caddy = audit_system(root).naive_caddyfile

            self.assertTrue(caddy["files"][0]["capabilities"]["forward_proxy"])
            self.assertTrue(caddy["files"][0]["capabilities"]["file_server"])
            self.assertTrue(caddy["files"][0]["capabilities"]["native_decoy"])
            self.assertEqual(
                caddy["binary_path"],
                "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
            )
            self.assertNotIn("content", caddy["files"][0])
            self.assertNotIn("secret", json.dumps(caddy))


if __name__ == "__main__":
    unittest.main()
