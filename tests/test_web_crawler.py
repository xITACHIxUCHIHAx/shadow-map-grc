import unittest
from unittest.mock import MagicMock, patch

from scanner.web_crawler import _origin, crawl_public_site
from scanner.web_security_scanner import WebSecurityError


BASE = "https://example.com/"




def mock_response(status=200, body=b"", headers=None):
    response = MagicMock()
    response.status_code = status
    response.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
    response.iter_content.return_value = [body] if body else []
    response.close.return_value = None
    return response


def validate_mock(url):
    if "@" in url or "127.0.0.1" in url:
        raise WebSecurityError("Blocked unsafe URL")
    return url.split("#", 1)[0]


class WebCrawlerOfflineTests(unittest.TestCase):
    @patch("scanner.web_crawler._validate_authorized_web_url",
           side_effect=validate_mock)
    @patch("scanner.web_crawler.requests.Session")
    def test_discovers_same_origin_links_and_records_forms(
        self, mock_session, _mock_validate
    ):
        session = mock_session.return_value
        response = mock_response(
            body=(
                b'<html><a href="/about">About</a>'
                b'<a href="https://other.example/path">External</a>'
                b'<form method="post" action="/login">'
                b'<input name="username"></form></html>'
            )
        )
        session.get.return_value = response

        result = crawl_public_site(BASE, max_pages=1, max_requests=5)

        self.assertEqual(len(result["pages"]), 1)
        self.assertIn("https://example.com/about", result["discovered_urls"])
        self.assertNotIn(
            "https://other.example/path", result["discovered_urls"]
        )
        self.assertEqual(len(result["forms"]), 1)
        self.assertEqual(result["forms"][0]["method"], "post")
        self.assertEqual(
            result["forms"][0]["action"], "https://example.com/login"
        )
        self.assertEqual(
            result["forms"][0]["enctype"],
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(len(result["forms"][0]["fields"]), 1)
        self.assertEqual(
            result["forms"][0]["fields"][0]["name"], "username"
        )
        session.get.assert_called_once()
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertTrue(session.get.call_args.kwargs["stream"])
        session.close.assert_called_once()
        response.close.assert_called_once()

    def test_form_inventory_captures_all_supported_field_types(self):
        from scanner.web_crawler import _DiscoveryParser

        parser = _DiscoveryParser()
        parser.feed(
            '<form method="post" action="/login" enctype="multipart/form-data">'
            '<input name="username" type="text" required autocomplete="username">'
            '<input name="password" type="password" required>'
            '<textarea name="comment" required></textarea>'
            '<select name="role" required>'
            '<option value="user">User</option>'
            '<option value="admin">Admin</option>'
            '</select>'
            '<button name="submit_action" type="submit">Submit</button>'
            '</form>'
        )

        self.assertEqual(len(parser.forms), 1)
        form = parser.forms[0]
        self.assertEqual(form["method"], "post")
        self.assertEqual(form["action"], "/login")
        self.assertEqual(form["enctype"], "multipart/form-data")
        self.assertEqual(
            [field["element"] for field in form["fields"]],
            ["input", "input", "textarea", "select", "button"],
        )
        self.assertEqual(form["fields"][0]["autocomplete"], "username")
        self.assertTrue(form["fields"][0]["required"])
        self.assertEqual(form["fields"][2]["type"], "textarea")
        self.assertEqual(
            form["fields"][3]["options"], ["user", "admin"]
        )
        self.assertEqual(form["fields"][4]["name"], "submit_action")

    @patch("scanner.web_crawler._validate_authorized_web_url",
           side_effect=validate_mock)
    @patch("scanner.web_crawler.requests.Session")
    def test_cross_origin_redirect_is_blocked(self, mock_session, _):
        session = mock_session.return_value
        response = mock_response(
            status=302,
            headers={"Location": "https://other.example/private"},
        )
        session.get.return_value = response

        result = crawl_public_site(BASE, max_pages=1, max_requests=5)

        self.assertEqual(len(result["pages"]), 1)
        self.assertEqual(result["pages"][0]["status_code"], 302)
        self.assertEqual(
            result["pages"][0]["blocked_redirect"],
            "cross-origin or invalid destination",
        )
        self.assertEqual(result["errors"], [])
        self.assertEqual(session.get.call_count, 1)
        response.close.assert_called()
        session.close.assert_called_once()

    @patch("scanner.web_crawler._validate_authorized_web_url",
           side_effect=validate_mock)
    @patch("scanner.web_crawler.requests.Session")
    def test_response_body_is_bounded(self, mock_session, _):
        session = mock_session.return_value
        response = mock_response(
            body=b"x" * 5000,
            headers={"Content-Type": "text/html"},
        )
        response.iter_content.return_value = [
            b"x" * 4096,
            b"x" * 4096,
        ]
        session.get.return_value = response

        result = crawl_public_site(
            BASE,
            max_pages=1,
            max_requests=5,
            max_body_bytes=1024,
        )

        self.assertEqual(len(result["pages"]), 1)
        self.assertTrue(result["pages"][0]["truncated"])
        self.assertEqual(result["limits"]["truncated_pages"], 1)
        response.close.assert_called_once()
        session.close.assert_called_once()

    def test_invalid_limits_are_rejected_before_network_use(self):
        invalid_limits = [
            {"max_pages": 0},
            {"max_requests": -1},
            {"max_body_bytes": 1000},
            {"max_urls": 0},
        ]

        with patch("scanner.web_crawler.requests.Session") as mock_session:
            for limits in invalid_limits:
                with self.subTest(limits=limits):
                    with self.assertRaises(WebSecurityError):
                        crawl_public_site(BASE, **limits)

            mock_session.assert_not_called()

    @patch("scanner.web_crawler._validate_authorized_web_url",
           side_effect=validate_mock)
    @patch("scanner.web_crawler.requests.Session")
    def test_robot_sitemap_references_are_discovered(
        self, mock_session, _
    ):
        session = mock_session.return_value
        robots = mock_response(
            body=b"User-agent: *\nDisallow: /private\n"
                 b"Sitemap: https://example.com/map.xml\n",
            headers={"Content-Type": "text/plain"},
        )
        home = mock_response(
            body=b"<html><p>Home</p></html>",
            headers={"Content-Type": "text/html"},
        )
        sitemap = mock_response(
            body=(
                b"<urlset><url><loc>https://example.com/docs</loc>"
                b"</url></urlset>"
            ),
            headers={"Content-Type": "application/xml"},
        )

        session.get.side_effect = [home, robots, sitemap]

        result = crawl_public_site(BASE, max_pages=3, max_requests=10)

        self.assertIn("https://example.com/docs", result["discovered_urls"])
        self.assertTrue(session.get.called)
        session.close.assert_called_once()


    def test_parser_captures_external_and_inline_javascript(self):
        from scanner.web_crawler import _DiscoveryParser

        parser = _DiscoveryParser()
        parser.feed(
            '<script src="/static/app.js"></script>'
            '<script>fetch("/api/v1/users");</script>'
        )

        self.assertIn("/static/app.js", parser.script_sources)
        self.assertTrue(
            any('/api/v1/users' in script for script in parser.inline_scripts)
        )


    def test_extracts_likely_api_endpoints_from_javascript(self):
        from scanner.web_crawler import _extract_javascript_endpoints

        script = """
        fetch("/api/v1/users");
        axios.get('/graphql');
        const login = "/auth/login";
        const swagger = "/swagger/index.html";
        const versioned = "/v2/accounts";
        const asset = "/static/site.css";
        """

        endpoints = _extract_javascript_endpoints(script)

        self.assertIn("/api/v1/users", endpoints)
        self.assertIn("/graphql", endpoints)
        self.assertIn("/auth/login", endpoints)
        self.assertIn("/swagger/index.html", endpoints)
        self.assertIn("/v2/accounts", endpoints)
        self.assertNotIn("/static/site.css", endpoints)

    def test_endpoint_extractor_accepts_bytes(self):
        from scanner.web_crawler import _extract_javascript_endpoints

        endpoints = _extract_javascript_endpoints(
            b'fetch("/api/v1/status")'
        )

        self.assertIn("/api/v1/status", endpoints)

    @patch("scanner.web_crawler._validate_authorized_web_url",
           side_effect=validate_mock)
    @patch("scanner.web_crawler.requests.Session")
    def test_external_javascript_discovers_api_endpoints(
        self, mock_session, _
    ):
        session = mock_session.return_value

        homepage = mock_response(
            body=(
                b'<html><script src="/static/app.js"></script></html>'
            ),
            headers={"Content-Type": "text/html"},
        )
        javascript = mock_response(
            body=b'fetch("/api/v1/users");',
            headers={"Content-Type": "application/javascript"},
        )
        session.get.side_effect = [homepage, javascript]

        result = crawl_public_site(
            BASE, max_pages=2, max_requests=5,
        )

        expected = "https://example.com/api/v1/users"
        self.assertIn(expected, result["api_endpoints"])
        self.assertIn(expected, result["discovered_urls"])
        self.assertEqual(len(result["pages"]), 2)
        self.assertEqual(session.get.call_count, 2)
        session.close.assert_called_once()
        homepage.close.assert_called_once()
        javascript.close.assert_called_once()


MAX_PAGES_TOO_MANY = 11


if __name__ == "__main__":
    unittest.main()


class WebCrawlerOriginTests(unittest.TestCase):
    def test_https_default_port_matches_explicit_443(self):
        self.assertEqual(
            _origin("https://example.com/"),
            _origin("https://example.com:443/"),
        )

    def test_http_default_port_matches_explicit_80(self):
        self.assertEqual(
            _origin("http://example.com/"),
            _origin("http://example.com:80/"),
        )

    def test_different_schemes_are_different_origins(self):
        self.assertNotEqual(
            _origin("http://example.com/"),
            _origin("https://example.com/"),
        )

    def test_different_custom_ports_are_different_origins(self):
        self.assertNotEqual(
            _origin("https://example.com:8443/"),
            _origin("https://example.com:9443/"),
        )

    def test_private_ip_and_custom_port_are_preserved(self):
        self.assertEqual(
            _origin("http://192.168.1.10:8080/"),
            ("http", "192.168.1.10", 8080),
        )

    def test_localhost_is_supported_as_an_origin(self):
        self.assertEqual(
            _origin("http://127.0.0.1:5000/"),
            ("http", "127.0.0.1", 5000),
        )
