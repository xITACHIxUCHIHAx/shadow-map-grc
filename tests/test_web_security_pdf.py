import unittest

from reporting.pdf_generator import build_web_security_pdf


class WebSecurityPDFTests(unittest.TestCase):
    def setUp(self):
        self.scan = {
            "id": 12,
            "target": "https://example.com",
            "status": "Completed",
            "started_at": "2026-11-05 10:00:00",
            "finished_at": "2026-11-05 10:00:05",
            "duration_seconds": 5.0,
            "error": None,
        }

    def test_generates_pdf_with_api_endpoints_and_form_metadata(self):
        result = {
            "target": "https://example.com",
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "notes": [],
            "discovery": {
                "pages": [
                    {
                        "url": "https://example.com/",
                        "status_code": 200,
                        "content_type": "text/html",
                        "truncated": False,
                    }
                ],
                "discovered_urls": ["https://example.com/login"],
                "api_endpoints": [
                    "https://example.com/api/v1/users",
                ],
                "forms": [
                    {
                        "page": "https://example.com/login",
                        "method": "post",
                        "action": "https://example.com/login",
                        "enctype": "application/x-www-form-urlencoded",
                        "fields": [
                            {
                                "name": "username",
                                "element": "input",
                                "type": "text",
                                "required": True,
                                "autocomplete": "username",
                                "options": [],
                            },
                            {
                                "name": "role",
                                "element": "select",
                                "type": None,
                                "required": False,
                                "autocomplete": None,
                                "options": ["user", "admin"],
                            },
                        ],
                    }
                ],
                "notes": [],
                "errors": [],
                "limits": {
                    "max_pages": 50,
                    "max_requests": 200,
                    "max_urls": 2000,
                    "urls_queued": 3,
                    "requests_used": 2,
                    "truncated_pages": 0,
                    "page_limit_reached": False,
                    "request_limit_reached": False,
                },
            },
        }

        pdf = build_web_security_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_generates_pdf_with_empty_discovery(self):
        result = {
            "target": "https://example.com",
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "notes": [],
            "discovery": {
                "pages": [],
                "discovered_urls": [],
                "forms": [],
                "notes": [],
                "errors": [],
                "limits": {},
            },
        }

        pdf = build_web_security_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_supports_older_discovery_records_without_new_metadata(self):
        result = {
            "target": "https://example.com",
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "notes": [],
            "discovery": {
                "pages": [],
                "discovered_urls": [],
                "forms": [
                    {
                        "page": "https://example.com/login",
                        "method": "post",
                        "action": "https://example.com/login",
                    }
                ],
                "notes": [],
                "errors": [],
                "limits": {},
            },
        }

        pdf = build_web_security_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)


if __name__ == "__main__":
    unittest.main()
