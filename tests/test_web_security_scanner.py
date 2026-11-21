import socket
import unittest
from unittest.mock import patch

from scanner.web_security_scanner import (
    WebSecurityError,
    _validate_public_https_url,
)


def approved_scope():
    return {
        "id": 1,
        "status": "Approved",
        "target": "https://example.com/",
        "ports_json": "[]",
        "paths_json": "[]",
        "excluded_paths_json": "[]",
        "profiles_json": '["standard"]',
        "techniques_json": "[]",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "max_requests": 50,
        "rate_limit_rps": 1000.0,
    }


class WebSecurityURLValidationTests(unittest.TestCase):
    def test_public_https_url_is_normalized(self):
        result = _validate_public_https_url(
            "https://8.8.8.8/example?mode=check#section"
        )
        self.assertEqual(
            result, "https://8.8.8.8/example?mode=check"
        )

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_hostname_without_scheme_defaults_to_https(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("93.184.216.34", 443))
        ]
        result = _validate_public_https_url("example.com/path")
        self.assertEqual(result, "https://example.com/path")
        mock_dns.assert_called_once()

    def test_http_is_rejected(self):
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("http://8.8.8.8/")

    def test_credentials_are_rejected(self):
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("https://user:pass@8.8.8.8/")

    def test_nonstandard_port_is_rejected(self):
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("https://8.8.8.8:8443/")

    def test_private_ip_is_rejected(self):
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("https://127.0.0.1/")

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_hostname_with_any_nonpublic_address_is_rejected(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.10", 443)),
        ]
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("example.com")

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_dns_failure_is_reported_safely(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("mock DNS failure")
        with self.assertRaises(WebSecurityError):
            _validate_public_https_url("example.com")


if __name__ == "__main__":
    unittest.main()


class WebSecurityMockedRequestTests(unittest.TestCase):
    @patch("scanner.web_security_scanner._validate_authorized_web_url",
           return_value="https://example.com/")
    @patch("scanner.web_security_scanner.requests.Session")
    def test_headers_and_cookie_flags_are_parsed(self, mock_session, _):
        from unittest.mock import MagicMock

        session = mock_session.return_value
        response = MagicMock()
        response.status_code = 200
        response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        response.raw.headers.getlist.return_value = [
            "sessionid=abc; Secure; HttpOnly; SameSite=Lax"
        ]
        session.get.return_value = response

        from unittest.mock import patch

        from scanner.web_security_scanner import scan_web_security

        discovery_result = {
            "target": "https://example.com/",
            "pages": [{"url": "https://example.com/", "status_code": 200}],
            "discovered_urls": [],
            "forms": [],
            "errors": [],
            "limits": {},
            "notes": [],
        }

        with patch(
            "scanner.web_crawler.crawl_public_site",
            return_value=discovery_result,
        ) as mock_crawl:
            result = scan_web_security("example.com")

        mock_crawl.assert_called_once()
        crawl_args = mock_crawl.call_args
        self.assertEqual(crawl_args.args[0], "https://example.com/")
        self.assertEqual(crawl_args.kwargs["profile"], "standard")
        self.assertIsNotNone(crawl_args.kwargs["request_budget"])
        self.assertEqual(result["discovery"], discovery_result)
        self.assertIsNone(result["discovery_error"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["target"], "https://example.com/")
        self.assertTrue(
            next(h for h in result["headers"]
                 if h["header"] == "strict-transport-security")["present"]
        )
        self.assertEqual(len(result["cookies"]), 1)
        self.assertTrue(result["cookies"][0]["secure"])
        self.assertTrue(result["cookies"][0]["httponly"])
        self.assertTrue(result["cookies"][0]["samesite"])
        session.get.assert_called_once()
        self.assertFalse(session.trust_env)
        self.assertTrue(session.get.call_args.kwargs["stream"])
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        response.close.assert_called_once()
        session.close.assert_called_once()

    @patch("scanner.web_crawler.crawl_public_site")
    @patch("scanner.web_security_scanner.requests.Session")
    @patch(
        "scanner.web_security_scanner._validate_authorized_web_url",
        return_value="https://example.com/",
    )
    def test_validated_redirect_is_followed_without_scope_approval(
        self, mock_validate, mock_session, mock_crawl
    ):
        from unittest.mock import MagicMock

        from scanner.web_security_scanner import scan_web_security

        session = mock_session.return_value

        first_response = MagicMock()
        first_response.status_code = 302
        first_response.headers = {
            "Location": "https://other.example/private",
        }
        first_response.raw.headers.getlist.return_value = []

        final_response = MagicMock()
        final_response.status_code = 200
        final_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
        }
        final_response.raw.headers.getlist.return_value = []

        session.get.side_effect = [first_response, final_response]
        mock_validate.side_effect = [
            "https://example.com/",
            "https://other.example/private",
        ]

        mock_crawl.return_value = {
            "target": "https://other.example/private",
            "pages": [],
            "discovered_urls": [],
            "api_endpoints": [],
            "forms": [],
            "errors": [],
            "blocked_urls": [],
            "deferred_urls": [],
            "limits": {},
            "notes": [],
        }

        result = scan_web_security("example.com")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(
            session.get.call_args_list[1].args[0],
            "https://other.example/private",
        )
        self.assertEqual(mock_validate.call_count, 2)
        self.assertNotIn("blocked_redirect", result)
        first_response.close.assert_called_once()
        final_response.close.assert_called_once()
        session.close.assert_called_once()
        mock_crawl.assert_called_once()



if __name__ == "__main__":
    unittest.main()


class AuthorizedWebTargetValidationTests(unittest.TestCase):
    def test_localhost_http_custom_port_is_accepted(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        result = _validate_authorized_web_url("http://127.0.0.1:8080/admin")
        self.assertEqual(result, "http://127.0.0.1:8080/admin")

    def test_private_ipv4_is_accepted(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        result = _validate_authorized_web_url("http://192.168.1.10:8080/")
        self.assertEqual(result, "http://192.168.1.10:8080/")

    def test_private_ipv6_is_accepted(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        result = _validate_authorized_web_url("http://[fd00::1]:8080/")
        self.assertEqual(result, "http://[fd00::1]:8080/")

    def test_public_ip_with_custom_https_port_is_accepted(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        result = _validate_authorized_web_url("https://8.8.8.8:8443/status")
        self.assertEqual(result, "https://8.8.8.8:8443/status")

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_internal_hostname_resolving_to_private_ip_is_accepted(self, mock_dns):
        from scanner.web_security_scanner import _validate_authorized_web_url

        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.25", 443))
        ]
        result = _validate_authorized_web_url("intranet.local")
        self.assertEqual(result, "https://intranet.local/")
        mock_dns.assert_called_once()

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_hostname_without_scheme_defaults_to_https(self, mock_dns):
        from scanner.web_security_scanner import _validate_authorized_web_url

        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        result = _validate_authorized_web_url("example.com/path")
        self.assertEqual(result, "https://example.com/path")

    def test_credentials_are_rejected(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("http://user:pass@192.168.1.10/")

    def test_unsupported_scheme_is_rejected(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("ftp://192.168.1.10/")

    def test_link_local_address_is_rejected(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("http://169.254.1.10/")

    def test_multicast_address_is_rejected(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("http://224.0.0.1/")

    def test_unspecified_address_is_rejected(self):
        from scanner.web_security_scanner import _validate_authorized_web_url

        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("http://0.0.0.0/")

    @patch("scanner.web_security_scanner.socket.getaddrinfo")
    def test_hostname_resolving_to_link_local_is_rejected(self, mock_dns):
        from scanner.web_security_scanner import _validate_authorized_web_url

        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.10.20", 443))
        ]
        with self.assertRaises(WebSecurityError):
            _validate_authorized_web_url("unsafe.internal")

class WebSecurityAssessmentIntegrationTests(unittest.TestCase):
    def test_incomplete_discovery_blocks_active_assessment(self):
        from unittest.mock import MagicMock, patch
        import requests

        from scanner.web_security_scanner import scan_web_security

        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.raw.headers.getlist.return_value = []
        session.get.return_value = response

        with (
            patch(
                "scanner.web_security_scanner.requests.Session",
                return_value=session,
            ),
            patch(
                "scanner.web_security_scanner.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("93.184.216.34", 443))
                ],
            ),
            patch(
                "scanner.web_crawler.crawl_public_site",
                side_effect=requests.RequestException("discovery failed"),
            ),
            patch(
                "scanner.web_app_assessment.run_reflected_input_checks"
            ) as xss_runner,
            patch(
                "scanner.web_app_assessment.run_sql_injection_checks"
            ) as sql_runner,
        ):
            result = scan_web_security("https://example.com/")

        xss_runner.assert_not_called()
        sql_runner.assert_not_called()

        self.assertEqual(
            result["reflected_input_assessment"]["status"], "not_run"
        )
        self.assertEqual(
            result["sql_injection_assessment"]["status"], "not_run"
        )
        self.assertIsNotNone(result["discovery_error"])

        response.close.assert_called_once()
        session.close.assert_called_once()

    def test_successful_discovery_runs_xss_and_sqli_without_scopes(self):
        from unittest.mock import MagicMock, patch

        from scanner.web_security_scanner import scan_web_security

        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.raw.headers.getlist.return_value = []
        session.get.return_value = response

        discovery = {
            "target": "https://example.com/",
            "pages": [{"url": "https://example.com/", "status_code": 200}],
            "discovered_urls": [
                "https://example.com/search?q=test",
                "https://example.com/item?id=1",
            ],
            "api_endpoints": [],
            "forms": [],
            "authentication_surfaces": [],
            "errors": [],
            "blocked_urls": [],
            "deferred_urls": [],
            "limits": {},
            "notes": [],
        }

        xss_result = {
            "status": "completed",
            "checks": [],
            "requests_used": 1,
            "requests_remaining": 49,
            "verified_vulnerabilities": 0,
            "notes": [],
        }
        sql_result = {
            "status": "completed",
            "checks": [],
            "requests_used": 2,
            "requests_remaining": 47,
            "verified_vulnerabilities": 0,
            "notes": [],
        }

        with (
            patch(
                "scanner.web_security_scanner.requests.Session",
                return_value=session,
            ),
            patch(
                "scanner.web_security_scanner.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("93.184.216.34", 443))
                ],
            ),
            patch(
                "scanner.web_crawler.crawl_public_site",
                return_value=discovery,
            ),
            patch(
                "scanner.web_app_assessment.run_reflected_input_checks",
                return_value=xss_result,
            ) as xss_runner,
            patch(
                "scanner.web_app_assessment.run_sql_injection_checks",
                return_value=sql_result,
            ) as sql_runner,
        ):
            result = scan_web_security("https://example.com/")

        xss_runner.assert_called_once()
        sql_runner.assert_called_once()

        for runner in (xss_runner, sql_runner):
            kwargs = runner.call_args.kwargs
            self.assertIs(kwargs["session"], session)
            self.assertIsNotNone(kwargs["budget"])
            self.assertNotIn("authorization_scopes", kwargs)

        self.assertEqual(
            result["reflected_input_assessment"]["status"], "completed"
        )
        self.assertEqual(
            result["sql_injection_assessment"]["status"], "completed"
        )

        response.close.assert_called_once()
        session.close.assert_called_once()
