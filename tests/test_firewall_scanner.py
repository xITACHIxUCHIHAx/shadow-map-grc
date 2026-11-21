import unittest

from scanner.firewall_scanner import (
    FirewallScanError,
    _parse_target,
)


class FirewallTargetParsingTests(unittest.TestCase):
    def test_bare_ipv4_defaults_to_https(self):
        self.assertEqual(
            _parse_target("192.0.2.10"),
            ("192.0.2.10", "https://192.0.2.10/"),
        )

    def test_bare_hostname_defaults_to_https(self):
        self.assertEqual(
            _parse_target("example.com"),
            ("example.com", "https://example.com/"),
        )

    def test_https_url_defaults_to_port_443(self):
        self.assertEqual(
            _parse_target("https://example.com"),
            ("example.com", "https://example.com/"),
        )

    def test_https_url_accepts_explicit_port(self):
        self.assertEqual(
            _parse_target("https://example.com:8443"),
            ("example.com", "https://example.com:8443/"),
        )

    def test_http_url_accepts_explicit_port(self):
        self.assertEqual(
            _parse_target("http://example.com:8001"),
            ("example.com", "http://example.com:8001/"),
        )

    def test_http_url_defaults_to_port_80(self):
        self.assertEqual(
            _parse_target("http://example.com"),
            ("example.com", "http://example.com/"),
        )

    def test_credentials_are_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("https://user:pass@example.com:8443/")

    def test_path_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("http://example.com:8001/admin")

    def test_query_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("https://example.com/?test=1")

    def test_fragment_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("https://example.com/#section")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("https://example.com:99999")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("ftp://example.com")

    def test_empty_target_is_rejected(self):
        with self.assertRaises(FirewallScanError):
            _parse_target("")


if __name__ == "__main__":
    unittest.main()


class FirewallScanMockTests(unittest.TestCase):
    def _run_mocked_scan(self, target, body_chunks=None):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        response = MagicMock()
        response.iter_content.return_value = iter(body_chunks or [])
        response.status_code = 200
        response.headers = {
            "Server": "Apache",
            "Content-Type": "text/html",
        }
        response.raw.headers.getlist.return_value = []
        response.is_redirect = False

        session = MagicMock()
        session.get.return_value = response

        with (
            patch.object(
                scanner, "_resolve_target_addresses",
                return_value=["192.0.2.10"],
            ) as resolver,
            patch.object(
                scanner, "_probe_tcp",
                return_value={
                    "port": 8001,
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "Mocked",
                    "duration_ms": 0,
                },
            ),
            patch.object(
                scanner, "_fingerprint_tcp_service",
                return_value={
                    "address": "192.0.2.10",
                    "port": 8001,
                    "protocol": "tcp",
                    "service": "http",
                    "product": None,
                    "version": None,
                    "confidence": "unknown",
                    "evidence": [],
                },
            ) as fingerprint,
            patch.object(
                scanner, "_inspect_tls",
                return_value={"available": True, "port": 8443},
            ) as tls_inspector,
            patch.object(
                scanner, "_PinnedHTTPAdapter"
            ) as http_adapter,
            patch.object(
                scanner, "_PinnedHTTPSAdapter"
            ) as https_adapter,
            patch.object(
                scanner.requests, "Session", return_value=session
            ),
        ):
            result = scanner.scan_firewall(target, tcp_ports=[8001])

        return (
            result, resolver, tls_inspector,
            http_adapter, https_adapter, session, response,
            fingerprint,
        )

    def test_full_scan_identifies_xampp_from_response_body(self):
        (
            result, resolver, tls_inspector,
            http_adapter, https_adapter, session, response, fingerprint,
        ) = self._run_mocked_scan(
            "http://example.com:8001",
            body_chunks=[
                b"<html><title>Welcome to XAMPP</title></html>"
            ],
        )

        self.assertEqual(len(result["services"]["items"]), 1)
        service = result["services"]["items"][0]
        self.assertEqual(service["port"], 8001)
        self.assertEqual(service["application"]["product"], "XAMPP")
        self.assertEqual(
            result["https"]["application"]["product"], "XAMPP"
        )
        self.assertNotIn(
            "Welcome to XAMPP",
            repr(result),
        )
        session.get.assert_called_once()
        response.iter_content.assert_called_once_with(chunk_size=1024)
        response.close.assert_called_once()

    def test_full_scan_does_not_retain_response_body(self):
        secret_marker = "PRIVATE-MOCK-PAGE-CONTENT"
        result, _, _, _, _, session, response, _ = self._run_mocked_scan(
            "http://example.com:8001",
            body_chunks=[f"<html>{secret_marker}</html>".encode()],
        )

        self.assertNotIn(secret_marker, repr(result))
        self.assertEqual(
            result["services"]["items"][0]["application"]["product"],
            "Apache HTTP Server",
        )
        session.get.assert_called_once()
        response.close.assert_called_once()

    def test_http_uses_pinned_http_adapter_and_url_port(self):
        (
            result, resolver, tls_inspector,
            http_adapter, https_adapter, session, response, fingerprint,
        ) = self._run_mocked_scan("http://example.com:8001")

        resolver.assert_called_once_with("example.com", 8001)
        http_adapter.assert_called_once_with(
            "192.0.2.10", "example.com", 8001
        )
        https_adapter.assert_not_called()
        tls_inspector.assert_not_called()

        fingerprint.assert_called_once_with("192.0.2.10", 8001)
        self.assertEqual(len(result["services"]["items"]), 1)
        self.assertEqual(result["services"]["items"][0]["service"], "http")

        self.assertTrue(result["https"]["checked"])
        self.assertEqual(result["https"]["scheme"], "http")
        self.assertEqual(result["https"]["port"], 8001)

        self.assertEqual(
            session.get.call_args.args[0],
            "http://example.com:8001/",
        )
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertTrue(session.get.call_args.kwargs["verify"])
        response.close.assert_called_once()
        session.close.assert_called_once()

    def test_https_uses_pinned_https_adapter_and_url_port(self):
        (
            result, resolver, tls_inspector,
            http_adapter, https_adapter, session, response, fingerprint,
        ) = self._run_mocked_scan("https://example.com:8443")

        resolver.assert_called_once_with("example.com", 8443)
        https_adapter.assert_called_once_with(
            "192.0.2.10", "example.com", 8443
        )
        http_adapter.assert_not_called()
        tls_inspector.assert_called_once_with(
            "example.com", "192.0.2.10", 8443
        )

        fingerprint.assert_called_once_with("192.0.2.10", 8001)
        self.assertEqual(len(result["services"]["items"]), 2)

        tcp_service = next(
            item for item in result["services"]["items"]
            if item["port"] == 8001
        )
        http_application = next(
            item for item in result["services"]["items"]
            if item["port"] == 8443
        )
        self.assertEqual(tcp_service["protocol"], "tcp")
        self.assertEqual(http_application["protocol"], "https")

        self.assertTrue(result["https"]["checked"])
        self.assertEqual(result["https"]["scheme"], "https")
        self.assertEqual(result["https"]["port"], 8443)
        self.assertTrue(result["tls"]["available"])

        self.assertEqual(
            session.get.call_args.args[0],
            "https://example.com:8443/",
        )
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertTrue(session.get.call_args.kwargs["verify"])
        response.close.assert_called_once()
        session.close.assert_called_once()




class FirewallServiceFingerprintTests(unittest.TestCase):
    def _fingerprint(self, banner=None, error=None, port=8001):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        if error:
            connection.recv.side_effect = error
        else:
            connection.recv.return_value = banner or b""

        with patch.object(
            scanner, "_connect_to_address", return_value=connection
        ) as connector:
            result = scanner._fingerprint_tcp_service(
                "192.0.2.10", port
            )

        connector.assert_called_once_with(
            "192.0.2.10", port, timeout=1.0
        )
        connection.settimeout.assert_called_once_with(1.0)

        if not error:
            connection.recv.assert_called_once_with(1024)

        return result

    def test_identifies_ssh_banner_and_version(self):
        result = self._fingerprint(
            b"SSH-2.0-OpenSSH_9.2p1 Debian-2"
        )

        self.assertEqual(result["service"], "ssh")
        self.assertEqual(result["product"], "OpenSSH")
        self.assertEqual(result["version"], "9.2p1")
        self.assertEqual(result["confidence"], "high")

    def test_identifies_ssh_after_informational_greeting(self):
        result = self._fingerprint(
            b"Authorized access only\r\n"
            b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"
        )

        self.assertEqual(result["service"], "ssh")
        self.assertEqual(result["product"], "OpenSSH")
        self.assertEqual(result["version"], "9.2p1")
        self.assertEqual(result["confidence"], "high")

    def test_identifies_ftp_from_explicit_greeting(self):
        result = self._fingerprint(
            b"220 FTP server ready",
            port=8001,
        )

        self.assertEqual(result["service"], "ftp")
        self.assertEqual(result["confidence"], "medium")

    def test_identifies_vsftpd_product_from_banner(self):
        result = self._fingerprint(
            b"220 (vsFTPd 3.0.5)",
            port=8001,
        )

        self.assertEqual(result["service"], "ftp")
        self.assertEqual(result["product"], "vsftpd")
        self.assertEqual(result["confidence"], "high")

    def test_does_not_infer_ftp_from_port_alone(self):
        result = self._fingerprint(
            b"220 Service ready",
            port=21,
        )

        self.assertEqual(result["service"], "unknown")

    def test_does_not_infer_smtp_from_port_alone(self):
        result = self._fingerprint(
            b"220 Service ready",
            port=25,
        )

        self.assertEqual(result["service"], "unknown")

    def test_identifies_smtp_from_esmtp_greeting(self):
        result = self._fingerprint(
            b"220 mail.example ESMTP Postfix",
            port=8001,
        )

        self.assertEqual(result["service"], "smtp")
        self.assertEqual(result["product"], "postfix")
        self.assertEqual(result["confidence"], "high")

    def test_identifies_imap_from_greeting(self):
        result = self._fingerprint(
            b"* OK IMAP server ready",
            port=8001,
        )

        self.assertEqual(result["service"], "imap")

    def test_identifies_pop3_from_greeting(self):
        result = self._fingerprint(
            b"+OK POP3 server ready",
            port=8001,
        )

        self.assertEqual(result["service"], "pop3")

    def test_empty_banner_remains_unknown(self):
        result = self._fingerprint(b"")

        self.assertEqual(result["service"], "unknown")
        self.assertNotIn("banner", result)

    def test_connection_error_is_reported_safely(self):
        result = self._fingerprint(error=OSError("mocked error"))

        self.assertEqual(result["service"], "unknown")
        self.assertEqual(result["error"], "OSError")
        self.assertNotIn("mocked error", str(result))




class FirewallSMBFingerprintTests(unittest.TestCase):
    def _run_fingerprint(self, response=None, error=None):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        if error:
            connection.recv.side_effect = error
        else:
            response = response or b""
            session_header = b"\x00" + len(response).to_bytes(3, "big")
            connection.recv.side_effect = [
                session_header,
                response,
            ]

        with patch.object(
            scanner, "_connect_to_address", return_value=connection
        ) as connector:
            result = scanner._fingerprint_smb_service(
                "192.0.2.10", 445
            )

        connector.assert_called_once_with(
            "192.0.2.10", 445, timeout=1.0
        )
        connection.settimeout.assert_called_once_with(1.0)

        if not error:
            request = connection.sendall.call_args.args[0]
            self.assertEqual(request[0], 0)
            self.assertEqual(request[4:8], b"\xfeSMB")

        return result

    @staticmethod
    def _valid_response(dialect=0x0202):
        response = bytearray(128)
        response[0:4] = b"\xfeSMB"
        response[4:6] = (64).to_bytes(2, "little")
        response[8:12] = (0).to_bytes(4, "little")
        response[12:14] = (0).to_bytes(2, "little")
        response[64:66] = (65).to_bytes(2, "little")
        response[68:70] = dialect.to_bytes(2, "little")
        return bytes(response)

    def test_identifies_smb2_and_selected_dialect(self):
        result = self._run_fingerprint(self._valid_response(0x0202))

        self.assertEqual(result["service"], "smb")
        self.assertEqual(result["version"], "2.0.2")
        self.assertEqual(result["confidence"], "high")
        self.assertIsNone(result["product"])

    def test_rejects_invalid_smb_signature(self):
        response = bytearray(self._valid_response())
        response[:4] = b"NOPE"

        result = self._run_fingerprint(bytes(response))

        self.assertEqual(result["service"], "unknown")

    def test_rejects_incomplete_response(self):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.recv.side_effect = [
            b"\x00\x00\x00\x80",
            self._valid_response()[:100],
            b"",
        ]

        with patch.object(
            scanner, "_connect_to_address", return_value=connection
        ):
            result = scanner._fingerprint_smb_service(
                "192.0.2.10", 445
            )

        self.assertEqual(result["service"], "unknown")
        self.assertIn("incomplete", " ".join(result["evidence"]).lower())

    def test_rejects_unsupported_dialect(self):
        result = self._run_fingerprint(
            self._valid_response(0x9999)
        )

        self.assertEqual(result["service"], "unknown")

    def test_connection_timeout_remains_unknown(self):
        import socket

        result = self._run_fingerprint(error=socket.timeout())

        self.assertEqual(result["service"], "unknown")
        self.assertEqual(result["error"], "TimeoutError")


class FirewallHTTPApplicationFingerprintTests(unittest.TestCase):
    def _fingerprint(self, server="", body="", scheme="http", port=8001):
        from scanner.firewall_scanner import _fingerprint_http_application

        return _fingerprint_http_application(
            "192.0.2.10",
            port,
            scheme,
            {"Server": server},
            body,
        )

    def test_identifies_xampp_from_explicit_dashboard_text(self):
        result = self._fingerprint(
            server="Apache/2.4.58",
            body="<title>Welcome to XAMPP</title>",
        )

        self.assertEqual(result["product"], "XAMPP")
        self.assertEqual(result["confidence"], "high")
        self.assertIsNone(result["version"])

    def test_identifies_wazuh_from_explicit_dashboard_text(self):
        result = self._fingerprint(
            body="<title>Wazuh Dashboard</title>",
        )

        self.assertEqual(result["product"], "Wazuh")
        self.assertEqual(result["confidence"], "high")

    def test_identifies_apache_without_claiming_xampp(self):
        result = self._fingerprint(
            server="Apache/2.4.58 (Unix)",
            body="<html><title>Example</title></html>",
        )

        self.assertEqual(result["product"], "Apache HTTP Server")
        self.assertEqual(result["version"], "2.4.58")
        self.assertNotEqual(result["product"], "XAMPP")

    def test_identifies_nginx_and_explicit_version(self):
        result = self._fingerprint(server="nginx/1.26.2")

        self.assertEqual(result["product"], "Nginx")
        self.assertEqual(result["version"], "1.26.2")

    def test_identifies_nginx_without_version(self):
        result = self._fingerprint(server="nginx")

        self.assertEqual(result["product"], "Nginx")
        self.assertIsNone(result["version"])

    def test_identifies_tomcat_from_apache_coyote_header(self):
        result = self._fingerprint(server="Apache-Coyote/1.1")

        self.assertEqual(result["product"], "Apache Tomcat")
        self.assertEqual(result["version"], "1.1")

    def test_unknown_server_is_not_guessed(self):
        result = self._fingerprint(
            server="ExampleServer",
            body="<html>Welcome</html>",
            port=55000,
        )

        self.assertIsNone(result["product"])
        self.assertIsNone(result["version"])
        self.assertEqual(result["confidence"], "medium")

    def test_https_protocol_is_preserved(self):
        result = self._fingerprint(
            server="nginx",
            scheme="https",
            port=8443,
        )

        self.assertEqual(result["protocol"], "https")
        self.assertEqual(result["service"], "https")
        self.assertEqual(result["port"], 8443)

    def test_bounded_body_reader_stops_at_four_kb(self):
        from unittest.mock import MagicMock
        from scanner.firewall_scanner import _read_bounded_response_body

        response = MagicMock()
        response.iter_content.return_value = iter([
            b"A" * 1024,
            b"B" * 1024,
            b"C" * 1024,
            b"D" * 1024,
            b"E" * 1024,
        ])

        body = _read_bounded_response_body(response)

        self.assertEqual(len(body), 4096)
        self.assertEqual(body, ("A" * 1024) + ("B" * 1024)
                         + ("C" * 1024) + ("D" * 1024))
        response.iter_content.assert_called_once_with(chunk_size=1024)


class FirewallRDPFingerprintTests(unittest.TestCase):
    @staticmethod
    def _response(response_type=2, value=1):
        payload = (
            b"\x0e\xd0"
            + b"\x00" * 5
            + bytes([response_type, 0])
            + (8).to_bytes(2, "little")
            + value.to_bytes(4, "little")
        )
        return b"\x03\x00" + (4 + len(payload)).to_bytes(2, "big") + payload

    def _run_fingerprint(self, response=None, error=None):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        if error:
            connection.recv.side_effect = error
        else:
            response = response or b""
            connection.recv.side_effect = [
                response[:4],
                response[4:],
                b"",
            ]

        with patch.object(
            scanner, "_connect_to_address", return_value=connection
        ) as connector:
            result = scanner._fingerprint_rdp_service(
                "192.0.2.10", 3389
            )

        connector.assert_called_once_with(
            "192.0.2.10", 3389, timeout=1.0
        )
        connection.settimeout.assert_called_once_with(1.0)

        if not error:
            request = connection.sendall.call_args.args[0]
            self.assertEqual(request[:4], b"\x03\x00\x00\x13")
            self.assertEqual(request[5], 0xe0)
            self.assertEqual(request[-8], 1)

        return result

    def test_identifies_rdp_with_tls_negotiation(self):
        result = self._run_fingerprint(self._response(2, 1))

        self.assertEqual(result["service"], "rdp")
        self.assertEqual(result["version"], "TLS")
        self.assertEqual(result["confidence"], "high")

    def test_identifies_rdp_with_credssp_negotiation(self):
        result = self._run_fingerprint(self._response(2, 2))

        self.assertEqual(result["service"], "rdp")
        self.assertEqual(result["version"], "CredSSP")

    def test_identifies_valid_rdp_negotiation_failure(self):
        result = self._run_fingerprint(self._response(3, 2))

        self.assertEqual(result["service"], "rdp")
        self.assertEqual(result["confidence"], "high")
        self.assertIn("failure code: 2", " ".join(result["evidence"]))

    def test_rejects_invalid_tpkt_signature(self):
        response = bytearray(self._response())
        response[0] = 4

        result = self._run_fingerprint(bytes(response))

        self.assertEqual(result["service"], "unknown")

    def test_rejects_incomplete_response(self):
        response = self._response()[:10]
        result = self._run_fingerprint(response)

        self.assertEqual(result["service"], "unknown")
        self.assertIn("incomplete", " ".join(result["evidence"]).lower())

    def test_rejects_unsupported_negotiation_type(self):
        result = self._run_fingerprint(self._response(9, 0))

        self.assertEqual(result["service"], "unknown")

    def test_timeout_remains_unknown(self):
        import socket

        result = self._run_fingerprint(error=socket.timeout())

        self.assertEqual(result["service"], "unknown")
        self.assertEqual(result["error"], "TimeoutError")


class FirewallDNSFingerprintTests(unittest.TestCase):
    def test_identifies_dns_from_valid_protocol_response(self):
        from unittest.mock import patch
        from scanner import firewall_scanner as scanner

        response = bytes.fromhex(
            "123481800001000000000000"
            "076578616d706c6503636f6d0000010001"
        )

        with patch("secrets.randbelow", return_value=0x1234), \
             patch.object(scanner.socket, "socket") as socket_factory:
            connection = socket_factory.return_value.__enter__.return_value
            connection.recvfrom.return_value = (response, ("192.0.2.10", 53))

            result = scanner._fingerprint_dns_service(
                "192.0.2.10", 53
            )

        self.assertEqual(result["service"], "dns")
        self.assertEqual(result["confidence"], "high")
        self.assertIn("DNS response", " ".join(result["evidence"]))
        connection.sendto.assert_called_once()
        connection.settimeout.assert_called_once_with(1.0)
        connection.recvfrom.assert_called_once_with(513)

    def test_rejects_response_with_wrong_transaction_id(self):
        from unittest.mock import patch
        from scanner import firewall_scanner as scanner

        response = bytes.fromhex(
            "999981800001000000000000"
            "076578616d706c6503636f6d0000010001"
        )

        with patch.object(
            scanner.socket, "create_connection"
        ) as connector:
            connection = connector.return_value.__enter__.return_value
            connection.recv.return_value = response

            result = scanner._fingerprint_dns_service(
                "192.0.2.10", 53
            )

        self.assertEqual(result["service"], "unknown")

    def test_timeout_remains_unknown(self):
        from unittest.mock import patch
        from scanner import firewall_scanner as scanner

        with patch.object(
            scanner.socket, "create_connection"
        ) as connector:
            connection = connector.return_value.__enter__.return_value
            connection.recv.side_effect = scanner.socket.timeout()

            result = scanner._fingerprint_dns_service(
                "192.0.2.10", 53
            )

        self.assertEqual(result["service"], "unknown")
        self.assertEqual(result["error"], "TimeoutError")

class FirewallDNSIntegrationTests(unittest.TestCase):
    def _run_scan(self, ports, tcp_state="closed", dns_service="dns"):
        from unittest.mock import MagicMock, patch
        from scanner import firewall_scanner as scanner

        response = MagicMock()
        response.iter_content.return_value = iter([])
        response.status_code = 200
        response.headers = {"Server": "Apache"}
        response.raw.headers.getlist.return_value = []
        response.is_redirect = False

        session = MagicMock()
        session.get.return_value = response

        dns_result = {
            "address": "192.0.2.10",
            "port": 53,
            "protocol": "udp",
            "service": dns_service,
            "product": None,
            "version": None,
            "confidence": "high" if dns_service == "dns" else "unknown",
            "evidence": [],
            "error": None,
        }

        with (
            patch.object(
                scanner, "_resolve_target_addresses",
                return_value=["192.0.2.10"],
            ),
            patch.object(
                scanner, "_probe_tcp",
                side_effect=lambda address, port: {
                    "address": address,
                    "port": port,
                    "protocol": "tcp",
                    "state": tcp_state,
                    "reason": "Mocked",
                    "duration_ms": 0,
                },
            ),
            patch.object(
                scanner, "_fingerprint_tcp_service",
                return_value={
                    "address": "192.0.2.10",
                    "port": 53,
                    "protocol": "tcp",
                    "service": "unknown",
                    "product": None,
                    "version": None,
                    "confidence": "unknown",
                    "evidence": [],
                },
            ) as tcp_probe,
            patch.object(
                scanner, "_fingerprint_smb_service",
                return_value={
                    "address": "192.0.2.10",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "smb",
                    "product": None,
                    "version": "2.0.2",
                    "confidence": "high",
                    "evidence": ["Mocked SMB2 negotiation"],
                },
            ) as smb_probe,
            patch.object(
                scanner, "_fingerprint_rdp_service",
                return_value={
                    "address": "192.0.2.10",
                    "port": 3389,
                    "protocol": "tcp",
                    "service": "rdp",
                    "product": None,
                    "version": None,
                    "confidence": "high",
                    "evidence": ["Mocked RDP negotiation"],
                },
            ) as rdp_probe,
            patch.object(
                scanner, "_fingerprint_dns_service",
                return_value=dns_result,
            ) as dns_probe,
            patch.object(
                scanner, "_inspect_tls",
                return_value={"available": False, "port": 443},
            ),
            patch.object(scanner, "_PinnedHTTPSAdapter"),
            patch.object(scanner, "_PinnedHTTPAdapter"),
            patch.object(scanner.requests, "Session", return_value=session),
        ):
            result = scanner.scan_firewall(
                "http://example.com",
                tcp_ports=ports,
            )

        return result, dns_probe, smb_probe, tcp_probe, rdp_probe

    def test_udp_dns_is_identified_in_service_results(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan([53], tcp_state="closed")

        dns_probe.assert_called_once_with("192.0.2.10", 53)
        dns_items = [
            item for item in result["services"]["items"]
            if item.get("protocol") == "udp"
        ]
        self.assertEqual(len(dns_items), 1)
        self.assertEqual(dns_items[0]["service"], "dns")

    def test_udp_dns_probe_runs_when_tcp_port_53_is_closed(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan([53], tcp_state="closed")

        dns_probe.assert_called_once()
        self.assertEqual(result["tcp"]["ports"][0]["state"], "closed")

    def test_udp_dns_probe_is_skipped_when_port_53_not_selected(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan([8001])

        dns_probe.assert_not_called()
        self.assertFalse(
            any(
                item.get("protocol") == "udp"
                for item in result["services"]["items"]
            )
        )



    def test_open_tcp_445_invokes_smb_negotiation(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [445], tcp_state="open"
        )

        smb_probe.assert_called_once_with("192.0.2.10", 445)
        tcp_probe.assert_not_called()

        smb_items = [
            item for item in result["services"]["items"]
            if item.get("service") == "smb"
        ]
        self.assertEqual(len(smb_items), 1)
        self.assertEqual(smb_items[0]["version"], "2.0.2")

    def test_closed_tcp_445_does_not_invoke_smb_negotiation(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [445], tcp_state="closed"
        )

        smb_probe.assert_not_called()
        tcp_probe.assert_not_called()
        self.assertFalse(
            any(item.get("service") == "smb"
                for item in result["services"]["items"])
        )

    def test_other_open_tcp_ports_keep_passive_fingerprinting(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [8001], tcp_state="open"
        )

        smb_probe.assert_not_called()
        tcp_probe.assert_called_once_with("192.0.2.10", 8001)

    def test_open_tcp_3389_invokes_rdp_negotiation(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [3389], tcp_state="open"
        )

        rdp_probe.assert_called_once_with("192.0.2.10", 3389)
        tcp_probe.assert_not_called()
        smb_probe.assert_not_called()

        rdp_items = [
            item for item in result["services"]["items"]
            if item.get("service") == "rdp"
        ]
        self.assertEqual(len(rdp_items), 1)
        self.assertEqual(rdp_items[0]["confidence"], "high")

    def test_closed_tcp_3389_does_not_invoke_rdp_negotiation(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [3389], tcp_state="closed"
        )

        rdp_probe.assert_not_called()
        tcp_probe.assert_not_called()
        self.assertFalse(
            any(item.get("service") == "rdp"
                for item in result["services"]["items"])
        )

    def test_other_open_ports_do_not_invoke_rdp_negotiation(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [8001], tcp_state="open"
        )

        rdp_probe.assert_not_called()
        tcp_probe.assert_called_once_with("192.0.2.10", 8001)

    def test_failed_udp_dns_probe_remains_unknown(self):
        result, dns_probe, smb_probe, tcp_probe, rdp_probe = self._run_scan(
            [53],
            tcp_state="closed",
            dns_service="unknown",
        )

        dns_probe.assert_called_once()
        dns_items = [
            item for item in result["services"]["items"]
            if item.get("protocol") == "udp"
        ]
        self.assertEqual(len(dns_items), 1)
        self.assertEqual(dns_items[0]["service"], "unknown")
        self.assertNotEqual(dns_items[0]["confidence"], "high")
