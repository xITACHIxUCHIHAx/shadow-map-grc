import unittest
import json
from unittest.mock import Mock, patch

from scanner.web_app_assessment import (
    AssessmentRequestBudget,
    _assessment_request,
    _send_pinned_request,
    _validate_assessment_url,
    normalize_assessment_target,
    AssessmentTargetValidationError,
    WebAssessmentRequestError,
    analyze_attack_surface,
    build_response_baseline,
    compare_sql_responses,
    compare_boolean_sql_responses,
    detect_sql_error_indicators,
    detect_reflected_input,
    run_reflected_input_checks,
    run_sql_injection_checks,
    _mutate_query_parameter,
    plan_vulnerability_assessment,
)


class WebAppAttackSurfaceTests(unittest.TestCase):
    def test_extracts_query_parameters_without_storing_values(self):
        discovery = {
            "target": "https://example.com/",
            "pages": [{"url": "https://example.com/search?q=test"}],
            "discovered_urls": [
                "https://example.com/search?q=secret&redirect=%2Faccount"
            ],
            "api_endpoints": ["https://example.com/api/v1/users"],
            "forms": [],
        }

        result = analyze_attack_surface(discovery)

        parameters = {
            item["name"]: item for item in result["parameters"]
        }
        self.assertIn("q", parameters)
        self.assertIn("redirect", parameters)
        self.assertNotIn("secret", str(result))
        self.assertEqual(parameters["q"]["source"], "query")
        self.assertTrue(parameters["q"]["value_present"])
        self.assertEqual(parameters["q"]["sql_context"], "unknown")
        self.assertEqual(parameters["redirect"]["sql_context"], "unknown")

    def test_extracts_form_fields_and_authentication_surfaces(self):
        discovery = {
            "target": "https://example.com/",
            "pages": [{"url": "https://example.com/login"}],
            "discovered_urls": [],
            "api_endpoints": ["https://example.com/api/auth/login"],
            "forms": [{
                "page": "https://example.com/login",
                "method": "post",
                "action": "https://example.com/session",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {
                        "element": "input",
                        "name": "username",
                        "type": "text",
                        "required": True,
                        "autocomplete": "username",
                    },
                    {
                        "element": "input",
                        "name": "password",
                        "type": "password",
                        "required": True,
                        "autocomplete": "current-password",
                    },
                ],
            }],
        }

        result = analyze_attack_surface(discovery)

        self.assertEqual(len(result["forms"]), 1)
        self.assertEqual(len(result["forms"][0]["fields"]), 2)
        self.assertTrue(
            any(
                item["type"] == "form"
                and item["location"] == "https://example.com/session"
                and item["method"] == "post"
                for item in result["authentication_surfaces"]
            )
        )
        self.assertTrue(
            any(item["type"] == "api_endpoint" for item in result["authentication_surfaces"])
        )
        self.assertTrue(
            any(item["type"] == "url" for item in result["authentication_surfaces"])
        )
        self.assertTrue(
            any(
                item["type"] == "form"
                and item["location"] == "https://example.com/session"
                for item in result["authentication_surfaces"]
            )
        )
        self.assertIn(
            "https://example.com/api/auth/login",
            result["api_endpoints"],
        )

    def test_preserves_form_action_authorization_metadata(self):
        base_form = {
            "page": "https://example.com/form",
            "method": "post",
            "action": "https://example.com/submit",
            "enctype": "application/x-www-form-urlencoded",
            "fields": [],
        }

        discovery = {
            "pages": [],
            "discovered_urls": [],
            "api_endpoints": [],
            "forms": [
                {**base_form, "action_authorized": True},
                {**base_form, "action_authorized": False},
                dict(base_form),
            ],
        }

        result = analyze_attack_surface(discovery)

        self.assertEqual(
            [form["action_authorized"] for form in result["forms"]],
            [True, False, None],
        )
        self.assertEqual(len(result["forms"]), 3)
        self.assertEqual(
            result["forms"][0]["enctype"],
            "application/x-www-form-urlencoded",
        )


    def test_passive_form_security_observations_require_authorized_actions(self):
        base_form = {
            "page": "https://example.com/login",
            "method": "post",
            "action": "http://example.com/session",
            "enctype": "application/x-www-form-urlencoded",
            "fields": [
                {"name": "password", "type": "password"},
                {"name": "csrf_token", "type": "hidden"},
            ],
        }

        discovery = {
            "pages": [],
            "discovered_urls": [],
            "api_endpoints": [],
            "forms": [
                {**base_form, "action_authorized": True},
                {**base_form, "action_authorized": False},
                dict(base_form),
            ],
        }

        result = analyze_attack_surface(discovery)
        observations = result["form_security"]

        self.assertEqual(
            [item["type"] for item in observations],
            [
                "password_field_over_http",
                "csrf_token_field_observed",
            ],
        )

        for item in observations:
            with self.subTest(observation=item["type"]):
                self.assertEqual(item["status"], "not_tested")
                self.assertEqual(item["confidence"], "none")
                self.assertEqual(item["evidence"], [])
                self.assertEqual(
                    item["form_action"],
                    "http://example.com/session",
                )
                self.assertEqual(item["method"], "post")

        self.assertEqual(
            [item["parameter"] for item in observations],
            ["password", "csrf_token"],
        )


    def test_classifies_parameters_for_vulnerability_assessment(self):
        discovery = {
            "pages": [{
                "url": (
                    "https://example.com/search?"
                    "id=10&q=hello&url=https%3A%2F%2Fexample.org"
                    "&file=report.pdf&username=admin"
                    "&redirect_url=https%3A%2F%2Fexample.org"
                    "&return_url=https%3A%2F%2Fexample.org"
                    "&webhook_url=https%3A%2F%2Fexample.org"
                    "&file_path=report.pdf&file_name=report.pdf"
                    "&cmd=status&command=ping&page=home&include=menu"
                )
            }],
            "discovered_urls": [],
            "api_endpoints": [],
            "forms": [],
        }

        result = analyze_attack_surface(discovery)
        parameters = {
            item["name"]: item
            for item in result["parameters"]
        }

        self.assertIn(
            "sql_injection",
            parameters["id"]["assessment_categories"],
        )
        self.assertIn(
            "xss",
            parameters["q"]["assessment_categories"],
        )
        self.assertIn(
            "ssrf",
            parameters["url"]["assessment_categories"],
        )
        self.assertIn(
            "path_traversal",
            parameters["file"]["assessment_categories"],
        )
        self.assertIn(
            "authentication_session",
            parameters["username"]["assessment_categories"],
        )

        for name in ("redirect_url", "return_url", "webhook_url"):
            with self.subTest(parameter=name):
                self.assertIn(
                    "ssrf",
                    parameters[name]["assessment_categories"],
                )

        for name in ("file_path", "file_name", "page", "include"):
            with self.subTest(parameter=name):
                self.assertIn(
                    "path_traversal",
                    parameters[name]["assessment_categories"],
                )

        for name in ("cmd", "command"):
            with self.subTest(parameter=name):
                self.assertIn(
                    "command_injection",
                    parameters[name]["assessment_categories"],
                )


    def test_malformed_discovery_metadata_is_handled(self):
        result = analyze_attack_surface({
            "pages": None,
            "discovered_urls": ["not a valid URL", None],
            "api_endpoints": None,
            "forms": [{"fields": None}],
        })

        self.assertEqual(result["parameters"], [])
        self.assertEqual(result["authentication_surfaces"], [])
        self.assertEqual(result["api_endpoints"], [])
        self.assertEqual(result["forms"], [])


class VulnerabilityAssessmentPlannerTests(unittest.TestCase):
    def test_plans_query_parameter_categories_without_testing(self):
        surface = {
            "parameters": [
                {
                    "name": "id",
                    "source": "query",
                    "location": "https://example.com/item",
                    "assessment_categories": ["sql_injection"],
                },
                {
                    "name": "q",
                    "source": "query",
                    "location": "https://example.com/search",
                    "assessment_categories": ["xss"],
                },
                {
                    "name": "url",
                    "source": "query",
                    "location": "https://example.com/fetch",
                    "assessment_categories": ["ssrf"],
                },
                {
                    "name": "file",
                    "source": "query",
                    "location": "https://example.com/download",
                    "assessment_categories": ["path_traversal"],
                },
                {
                    "name": "cmd",
                    "source": "query",
                    "location": "https://example.com/tools",
                    "assessment_categories": ["command_injection"],
                },
            ],
            "forms": [],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        categories = {
            item["category"] for item in result["candidates"]
        }
        self.assertEqual(
            categories,
            {
                "sql_injection", "xss", "ssrf", "path_traversal",
                "command_injection",
            },
        )
        self.assertEqual(result["status"], "planned")
        self.assertTrue(
            all(item["status"] == "not_tested" for item in result["candidates"])
        )
        replay_eligible = {
            item["category"]: item["replay_eligible"]
            for item in result["candidates"]
        }
        self.assertTrue(replay_eligible["sql_injection"])
        self.assertTrue(replay_eligible["xss"])
        self.assertFalse(replay_eligible["ssrf"])
        self.assertFalse(replay_eligible["path_traversal"])
        self.assertFalse(replay_eligible["command_injection"])

        candidates_by_category = {
            item["category"]: item for item in result["candidates"]
        }

        self.assertEqual(
            candidates_by_category["ssrf"]["indicators"][0]["type"],
            "parameter_name_pattern",
        )
        self.assertEqual(
            candidates_by_category["path_traversal"]["indicators"][0]["type"],
            "parameter_name_pattern",
        )
        self.assertEqual(
            candidates_by_category["command_injection"]["indicators"][0]["type"],
            "parameter_name_pattern",
        )

        for item in result["candidates"]:
            with self.subTest(category=item["category"]):
                self.assertEqual(item["status"], "not_tested")
                self.assertEqual(item["evidence"], [])
                self.assertEqual(item["confidence"], "none")

    def test_planner_rejects_forged_parameter_categories(self):
        surface = {
            "parameters": [
                {
                    "name": "ordinary_parameter",
                    "source": "query",
                    "location": "https://example.com/item",
                    "assessment_categories": ["sql_injection", "xss"],
                },
            ],
            "forms": [],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["sql_injection_checks"], [])
        self.assertEqual(result["reflected_input_checks"], [])


    def test_form_ssrf_and_path_traversal_candidates_are_review_only(self):
        discovery = {
            "pages": [],
            "discovered_urls": [],
            "api_endpoints": [],
            "forms": [{
                "page": "https://example.com/settings",
                "method": "post",
                "action": "https://example.com/settings",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {"name": "callback_url", "type": "text"},
                    {"name": "file_path", "type": "text"},
                ],
            }],
        }

        surface = analyze_attack_surface(discovery)
        result = plan_vulnerability_assessment(surface)

        candidates = {
            item["category"]: item
            for item in result["candidates"]
            if item["source"] == "form"
        }

        self.assertIn("ssrf", candidates)
        self.assertIn("path_traversal", candidates)

        for category in ("ssrf", "path_traversal"):
            with self.subTest(category=category):
                candidate = candidates[category]
                self.assertFalse(candidate["replay_eligible"])
                self.assertEqual(candidate["status"], "not_tested")
                self.assertEqual(candidate["evidence"], [])
                self.assertEqual(candidate["confidence"], "none")
                self.assertEqual(
                    candidate["indicators"][0]["type"],
                    "parameter_name_pattern",
                )


    def test_never_marks_sensitive_or_post_form_fields_replay_eligible(self):
        surface = {
            "parameters": [
                {
                    "name": "password",
                    "source": "query",
                    "location": "https://example.com/login",
                    "assessment_categories": ["authentication_session"],
                },
                {
                    "name": "token",
                    "source": "query",
                    "location": "https://example.com/callback",
                    "assessment_categories": ["authentication_session"],
                },
            ],
            "forms": [
                {
                    "method": "post",
                    "action": "https://example.com/search",
                    "fields": [
                        {"name": "q", "type": "text"},
                        {"name": "password", "type": "password"},
                    ],
                },
                {
                    "method": "get",
                    "action": "https://example.com/search",
                    "fields": [
                        {"name": "q", "type": "text"},
                        {"name": "csrf", "type": "hidden"},
                    ],
                },
            ],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        for candidate in result["candidates"]:
            if candidate["parameter"] in {"password", "token", "csrf"}:
                self.assertFalse(candidate["replay_eligible"])

        post_candidates = [
            item for item in result["candidates"]
            if item["source"] == "form"
            and item["location"] == "https://example.com/search"
            and item["parameter"] == "q"
            and not item["replay_eligible"]
        ]
        self.assertEqual(len(post_candidates), 1)

    def test_generic_form_fields_use_authentication_metadata(self):
        surface = {
            "parameters": [],
            "forms": [{
                "method": "post",
                "action": "https://example.com/account",
                "fields": [
                    {
                        "name": "input1",
                        "type": "password",
                    },
                    {
                        "name": "input2",
                        "type": "text",
                        "autocomplete": "current-password",
                    },
                    {
                        "name": "input3",
                        "type": "hidden",
                        "autocomplete": "one-time-code",
                    },
                ],
            }],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        auth_candidates = [
            item for item in result["candidates"]
            if item["source"] == "form"
            and item["category"] == "authentication_session"
        ]

        self.assertEqual(
            {item["parameter"] for item in auth_candidates},
            {"input1", "input2", "input3"},
        )
        self.assertTrue(
            all(not item["replay_eligible"] for item in auth_candidates)
        )
        self.assertTrue(
            all(item["status"] == "not_tested" for item in auth_candidates)
        )

    def test_authentication_parameters_are_never_replay_eligible(self):
        surface = {
            "parameters": [
                {
                    "name": name,
                    "source": "query",
                    "location": "https://example.com/account",
                    "assessment_categories": ["authentication_session"],
                }
                for name in ("username", "user", "email", "csrf")
            ],
            "forms": [{
                "method": "get",
                "action": "https://example.com/account",
                "fields": [
                    {"name": name, "type": "text"}
                    for name in ("username", "user", "email", "csrf", "q")
                ],
            }],
        }

        result = plan_vulnerability_assessment(surface)

        auth_candidates = [
            item for item in result["candidates"]
            if item["parameter"] in {"username", "user", "email", "csrf"}
        ]

        self.assertEqual(len(auth_candidates), 10)
        self.assertTrue(
            all(not item["replay_eligible"] for item in auth_candidates)
        )

        search_candidates = [
            item for item in result["candidates"]
            if item["source"] == "form"
            and item["parameter"] == "q"
        ]
        self.assertEqual(len(search_candidates), 1)
        self.assertFalse(search_candidates[0]["replay_eligible"])
        self.assertEqual(search_candidates[0]["status"], "not_tested")
        self.assertEqual(search_candidates[0]["evidence"], [])
        self.assertEqual(search_candidates[0]["confidence"], "none")


    def test_sql_injection_checks_are_bounded_and_query_only(self):
        surface = {
            "parameters": [
                {
                    "name": f"id{number}",
                    "source": "query",
                    "location": "https://example.com/search",
                    "assessment_categories": ["sql_injection"],
                }
                for number in range(15)
            ],
            "forms": [],
            "authentication_surfaces": [],
        }

        with patch(
            "scanner.web_app_assessment._classify_parameter",
            return_value=["sql_injection"],
        ):
            result = plan_vulnerability_assessment(surface)

        checks = result["sql_injection_checks"]
        self.assertEqual(len(checks), 10)
        self.assertTrue(
            all(item["method"] == "GET" for item in checks)
        )
        self.assertTrue(
            all(item["probe"] == "single_quote" for item in checks)
        )
        self.assertTrue(
            all(item["status"] == "not_tested" for item in checks)
        )

    def test_sql_injection_checks_exclude_authentication_and_forms(self):
        surface = {
            "parameters": [
                {
                    "name": "username",
                    "source": "query",
                    "location": "https://example.com/login",
                    "assessment_categories": [
                        "sql_injection",
                        "authentication_session",
                    ],
                },
                {
                    "name": "id",
                    "source": "query",
                    "location": "https://example.com/item",
                    "assessment_categories": ["sql_injection"],
                },
            ],
            "forms": [{
                "method": "get",
                "action": "https://example.com/search",
                "fields": [{"name": "id", "type": "text"}],
            }],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        self.assertEqual(len(result["sql_injection_checks"]), 1)
        self.assertEqual(
            result["sql_injection_checks"][0]["parameter"], "id"
        )
        self.assertEqual(
            result["sql_injection_checks"][0]["location"],
            "https://example.com/item",
        )

    def test_boolean_sql_injection_checks_are_separate_and_query_only(self):
        surface = {
            "parameters": [
                {
                    "name": "username",
                    "source": "query",
                    "location": "https://example.com/login",
                },
                {
                    "name": "id",
                    "source": "query",
                    "location": "https://example.com/item",
                },
            ],
            "forms": [{
                "method": "get",
                "action": "https://example.com/search",
                "fields": [{"name": "id", "type": "text"}],
            }],
            "authentication_surfaces": [],
        }

        with patch(
            "scanner.web_app_assessment._classify_parameter",
            return_value=["sql_injection"],
        ):
            result = plan_vulnerability_assessment(surface)

        boolean_checks = result["sql_boolean_based_checks"]
        self.assertEqual(len(boolean_checks), 1)
        self.assertEqual(boolean_checks[0]["parameter"], "id")
        self.assertEqual(boolean_checks[0]["method"], "GET")
        self.assertEqual(
            boolean_checks[0]["probe"], "boolean_condition_pair"
        )
        self.assertEqual(boolean_checks[0]["status"], "not_tested")
        self.assertEqual(boolean_checks[0]["confidence"], "none")
        self.assertEqual(boolean_checks[0]["sql_context"], "unknown")
        self.assertTrue(boolean_checks[0]["review_only"])
        self.assertFalse(boolean_checks[0]["verified"])

        # The original error-based SQLi path remains independent.
        error_checks = result["sql_injection_checks"]
        self.assertEqual(len(error_checks), 1)
        self.assertEqual(error_checks[0]["parameter"], "id")
        self.assertEqual(error_checks[0]["probe"], "single_quote")


    def test_authentication_surfaces_are_review_only(self):
        result = plan_vulnerability_assessment({
            "parameters": [],
            "forms": [],
            "authentication_surfaces": [
                {
                    "type": "form",
                    "location": "https://example.com/login",
                    "method": "post",
                }
            ],
        })

        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["category"], "authentication_session")
        self.assertFalse(candidate["replay_eligible"])
        self.assertEqual(candidate["status"], "not_tested")

    def test_malformed_planner_input_returns_empty_plan(self):
        result = plan_vulnerability_assessment(None)

        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["summary"]["total"], 0)


class WebAssessmentProfileTests(unittest.TestCase):
    def _surface_with_sql_parameters(self, count):
        return {
            "parameters": [
                {
                    "name": f"id{number}",
                    "source": "query",
                    "location": "https://example.com/search",
                    "assessment_categories": ["sql_injection"],
                }
                for number in range(count)
            ],
            "forms": [],
            "authentication_surfaces": [],
        }

    def test_profiles_return_expected_limits(self):
        expected = {
            "standard": (50, 262144, 5, 10, 5, 10),
            "comprehensive": (250, 524288, 8, 50, 25, 50),
            "deep": (500, 1048576, 10, 100, 50, 100),
        }

        for profile, limits in expected.items():
            with self.subTest(profile=profile):
                result = plan_vulnerability_assessment(
                    {}, profile=profile
                )
                self.assertEqual(result["profile"], profile)
                self.assertEqual(
                    (
                        result["profile_limits"]["max_requests"],
                        result["profile_limits"]["max_body_bytes"],
                        result["profile_limits"]["max_redirects"],
                        result["profile_limits"]["max_sqli_candidates"],
                        result["profile_limits"][
                            "max_boolean_sqli_candidates"
                        ],
                        result["profile_limits"][
                            "max_reflected_input_candidates"
                        ],
                    ),
                    limits,
                )

    def test_sql_candidate_count_respects_each_profile(self):
        expected = {
            "standard": 10,
            "comprehensive": 50,
            "deep": 100,
        }

        for profile, maximum in expected.items():
            with self.subTest(profile=profile):
                surface = self._surface_with_sql_parameters(120)
                with patch(
                    "scanner.web_app_assessment._classify_parameter",
                    return_value=["sql_injection"],
                ):
                    result = plan_vulnerability_assessment(
                        surface, profile=profile
                    )
                self.assertEqual(
                    len(result["sql_injection_checks"]), maximum
                )

    def test_boolean_sql_candidate_count_respects_each_profile(self):
        expected = {
            "standard": 5,
            "comprehensive": 25,
            "deep": 50,
        }

        for profile, maximum in expected.items():
            with self.subTest(profile=profile):
                surface = self._surface_with_sql_parameters(120)
                with patch(
                    "scanner.web_app_assessment._classify_parameter",
                    return_value=["sql_injection"],
                ):
                    result = plan_vulnerability_assessment(
                        surface, profile=profile
                    )

                checks = result["sql_boolean_based_checks"]
                self.assertEqual(len(checks), maximum)
                self.assertTrue(
                    all(item["method"] == "GET" for item in checks)
                )
                self.assertTrue(
                    all(
                        item["probe"] == "boolean_condition_pair"
                        for item in checks
                    )
                )
                self.assertTrue(
                    all(item["status"] == "not_tested" for item in checks)
                )
                self.assertTrue(
                    all(item["sql_context"] == "unknown" for item in checks)
                )
                self.assertTrue(
                    all(item["review_only"] for item in checks)
                )
                self.assertTrue(
                    all(not item["verified"] for item in checks)
                )

    def test_reflected_input_checks_respect_each_profile_limit(self):
        expected = {
            "standard": 10,
            "comprehensive": 50,
            "deep": 100,
        }

        for profile, maximum in expected.items():
            with self.subTest(profile=profile):
                surface = {
                    "parameters": [
                        {
                            "name": f"q{number}",
                            "source": "query",
                            "location": (
                                f"https://example.com/search?page={number}"
                            ),
                            "assessment_categories": ["xss"],
                        }
                        for number in range(120)
                    ],
                    "forms": [],
                    "authentication_surfaces": [],
                }

                with patch(
                    "scanner.web_app_assessment._classify_parameter",
                    return_value=["xss"],
                ):
                    result = plan_vulnerability_assessment(
                        surface, profile=profile
                    )
                checks = result["reflected_input_checks"]

                self.assertEqual(len(checks), maximum)
                self.assertTrue(
                    all(item["method"] == "GET" for item in checks)
                )
                self.assertTrue(
                    all(
                        item["probe"] == "unique_reflection_marker"
                        for item in checks
                    )
                )
                self.assertTrue(
                    all(item["status"] == "not_tested" for item in checks)
                )
                self.assertTrue(
                    all(not item["verified"] for item in checks)
                )

    def test_reflected_input_checks_exclude_forms_and_authentication(self):
        surface = {
            "parameters": [
                {
                    "name": "q",
                    "source": "query",
                    "location": "https://example.com/search",
                    "assessment_categories": ["xss"],
                },
                {
                    "name": "token",
                    "source": "query",
                    "location": "https://example.com/account",
                    "assessment_categories": ["xss", "authentication_session"],
                },
            ],
            "forms": [{
                "method": "get",
                "action": "https://example.com/search",
                "fields": [{"name": "q", "type": "text"}],
            }],
            "authentication_surfaces": [],
        }

        result = plan_vulnerability_assessment(surface)

        self.assertEqual(len(result["reflected_input_checks"]), 1)
        self.assertEqual(
            result["reflected_input_checks"][0]["parameter"], "q"
        )
        self.assertEqual(
            result["reflected_input_checks"][0]["location"],
            "https://example.com/search",
        )

    def test_default_profile_is_standard(self):
        result = plan_vulnerability_assessment({})
        self.assertEqual(result["profile"], "standard")
        self.assertEqual(
            result["profile_limits"]["max_sqli_candidates"], 10
        )

    def test_invalid_profile_is_rejected(self):
        for profile in ("unknown", "", None):
            if profile is None:
                continue
            with self.subTest(profile=profile):
                with self.assertRaises(WebAssessmentRequestError):
                    plan_vulnerability_assessment({}, profile=profile)


class WebAssessmentRequestTests(unittest.TestCase):
    def setUp(self):
        self.pinned_adapters = []
        self._pinned_request_patcher = patch(
            "scanner.web_app_assessment._send_pinned_request",
            side_effect=self._mock_pinned_request,
        )
        self.mock_pinned_request = self._pinned_request_patcher.start()

    def tearDown(self):
        self._pinned_request_patcher.stop()
        for adapter in self.pinned_adapters:
            adapter.close.assert_called_once()

    def _mock_pinned_request(self, session, method, url, **kwargs):
        response = session.request(
            method,
            url,
            params=kwargs.get("params"),
            data=kwargs.get("data"),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        return self._pinned_request(response)

    def _response(self, chunks):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.iter_content.return_value = iter(chunks)
        return response

    def _pinned_request(self, response, adapter=None):
        if adapter is None:
            adapter = Mock()
        self.pinned_adapters.append(adapter)
        return response, adapter
    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_rejects_redirect_to_unsupported_destination(self, validate_url):
        validate_url.side_effect = [
            "http://127.0.0.1/",
            "http://127.0.0.1/",
            WebAssessmentRequestError(
                "Assessment destination resolves to an unsupported address."
            ),
        ]
        response = Mock()
        response.status_code = 302
        response.headers = {"Location": "http://169.254.10.20/"}
        response.close = Mock()

        session = Mock()
        session.request.return_value = response

        with self.assertRaises(WebAssessmentRequestError):
            _assessment_request(
                session, "GET", "http://127.0.0.1/"
            )

        self.assertEqual(session.request.call_count, 1)
        response.close.assert_called_once()

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_profile_timeout_is_passed_to_http_request(self, validate_url):
        validate_url.side_effect = lambda value: value

        expected = {
            "standard": (3, 7),
            "comprehensive": (5, 10),
            "deep": (5, 15),
        }

        for profile, timeout in expected.items():
            with self.subTest(profile=profile):
                response = self._response([b"OK"])
                session = Mock()
                session.request.return_value = response
                budget = AssessmentRequestBudget(profile=profile)

                _assessment_request(
                    session, "GET", "http://127.0.0.1/",
                    budget=budget,
                )

                self.assertEqual(
                    session.request.call_args.kwargs["timeout"],
                    timeout,
                )
                response.close.assert_called_once()

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_profile_redirect_limit_is_enforced(self, validate_url):
        validate_url.side_effect = lambda value: value

        redirect = Mock()
        redirect.status_code = 302
        redirect.headers = {"Location": "/next"}

        session = Mock()
        session.request.return_value = redirect
        budget = AssessmentRequestBudget(profile="standard")

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "Redirect limit exceeded"
        ):
            _assessment_request(
                session, "GET", "http://127.0.0.1/",
                budget=budget,
            )

        self.assertEqual(session.request.call_count, 6)
        self.assertEqual(budget.used, 6)
        self.assertEqual(redirect.close.call_count, 6)

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_body_limit_cannot_exceed_selected_profile(self, validate_url):
        validate_url.side_effect = lambda value: value
        session = Mock()
        budget = AssessmentRequestBudget(profile="standard")

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "Invalid response size limit"
        ):
            _assessment_request(
                session, "GET", "http://127.0.0.1/",
                max_body_bytes=262145,
                budget=budget,
            )

        session.request.assert_not_called()


    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_normal_request_consumes_one_budget_unit(self, validate_url):
        validate_url.side_effect = lambda value: value
        response = self._response([b"OK"])
        session = Mock()
        session.request.return_value = response
        budget = AssessmentRequestBudget(maximum=2)

        _assessment_request(
            session, "GET", "http://127.0.0.1/",
            budget=budget,
        )

        self.assertEqual(budget.used, 1)
        self.assertEqual(budget.remaining, 1)
        session.request.assert_called_once()
        response.close.assert_called_once()

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_redirect_consumes_budget_for_each_request(self, validate_url):
        validate_url.side_effect = lambda value: value

        redirect = Mock()
        redirect.status_code = 302
        redirect.headers = {"Location": "/next"}

        success = self._response([b"OK"])

        session = Mock()
        session.request.side_effect = [redirect, success]
        budget = AssessmentRequestBudget(maximum=2)

        result = _assessment_request(
            session, "GET", "http://127.0.0.1/",
            budget=budget,
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(budget.used, 2)
        self.assertEqual(budget.remaining, 0)
        self.assertEqual(session.request.call_count, 2)
        redirect.close.assert_called_once()
        success.close.assert_called_once()

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_exhausted_budget_blocks_request_after_redirect(self, validate_url):
        validate_url.side_effect = lambda value: value

        redirect = Mock()
        redirect.status_code = 302
        redirect.headers = {"Location": "/next"}

        session = Mock()
        session.request.return_value = redirect
        budget = AssessmentRequestBudget(maximum=1)

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "budget exhausted"
        ):
            _assessment_request(
                session, "GET", "http://127.0.0.1/",
                budget=budget,
            )

        self.assertEqual(budget.used, 1)
        self.assertEqual(session.request.call_count, 1)
        redirect.close.assert_called_once()


    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_exact_response_limit_is_not_truncated(self, validate_url):
        validate_url.side_effect = lambda value: value
        response = self._response([b"1234"])
        session = Mock()
        session.request.return_value = response

        result = _assessment_request(
            session, "GET", "http://127.0.0.1/", max_body_bytes=4
        )

        self.assertEqual(result["body"], b"1234")
        self.assertFalse(result["truncated"])
        response.close.assert_called_once()

    @patch("scanner.web_app_assessment._validate_assessment_url")
    def test_response_over_limit_is_truncated(self, validate_url):
        validate_url.side_effect = lambda value: value
        response = self._response([b"12345"])
        session = Mock()
        session.request.return_value = response

        result = _assessment_request(
            session, "GET", "http://127.0.0.1/", max_body_bytes=4
        )

        self.assertEqual(result["body"], b"1234")
        self.assertTrue(result["truncated"])
        response.close.assert_called_once()


class AssessmentURLValidationTests(unittest.TestCase):
    def test_accepts_private_and_loopback_targets(self):
        self.assertEqual(
            _validate_assessment_url("http://127.0.0.1:5000/test"),
            "http://127.0.0.1:5000/test",
        )
        self.assertEqual(
            _validate_assessment_url("https://192.168.1.10/"),
            "https://192.168.1.10/",
        )

    def test_rejects_credentials_and_unsupported_schemes(self):
        invalid_urls = [
            "ftp://example.com/",
            "http://user:pass@example.com/",
            "http://example.com:0/",
            "not-a-url",
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(WebAssessmentRequestError):
                    _validate_assessment_url(url)

    @patch("scanner.web_app_assessment.socket.getaddrinfo")
    def test_rejects_hostname_resolving_to_link_local_address(self, resolve):
        resolve.return_value = [
            (2, 1, 6, "", ("169.254.10.20", 80))
        ]

        with self.assertRaises(WebAssessmentRequestError):
            _validate_assessment_url("http://internal.example/")


class SQLErrorIndicatorTests(unittest.TestCase):
    def test_detects_supported_database_error_signatures(self):
        samples = {
            "mysql": "You have an error in your SQL syntax",
            "postgresql": "PostgreSQL error: syntax error at or near SELECT",
            "microsoft_sql_server": "Unclosed quotation mark after the character string",
            "oracle": "ORA-00933: SQL command not properly ended",
            "sqlite": "sqlite3.OperationalError: near SELECT: syntax error",
        }

        for family, body in samples.items():
            with self.subTest(database=family):
                result = detect_sql_error_indicators(body)
                self.assertEqual(result["status"], "suspected")
                self.assertIn(family, result["database_families"])
                self.assertTrue(result["indicators"])
                self.assertFalse(result["verified"])

    def test_clean_response_has_no_sql_error_indicators(self):
        result = detect_sql_error_indicators(
            "Welcome to the application. Your request was successful."
        )
        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["confidence"], "none")
        self.assertEqual(result["database_families"], [])
        self.assertFalse(result["verified"])

    def test_multiple_database_families_produce_medium_confidence(self):
        result = detect_sql_error_indicators(
            "ORA-00933: SQL command not properly ended; "
            "You have an error in your SQL syntax"
        )
        self.assertEqual(result["status"], "suspected")
        self.assertEqual(result["confidence"], "medium")
        self.assertEqual(
            set(result["database_families"]),
            {"oracle", "mysql"},
        )
        self.assertFalse(result["verified"])

    def test_ordinary_sql_related_text_is_not_detected(self):
        result = detect_sql_error_indicators(
            "SQL query completed successfully. "
            "The database connection is healthy."
        )
        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["database_families"], [])
        self.assertFalse(result["verified"])

    def test_error_signature_matching_is_case_insensitive(self):
        result = detect_sql_error_indicators(
            "YOU HAVE AN ERROR IN YOUR SQL SYNTAX"
        )
        self.assertEqual(result["status"], "suspected")
        self.assertIn("mysql", result["database_families"])
        self.assertFalse(result["verified"])

    def test_accepts_byte_response_content(self):
        result = detect_sql_error_indicators(
            b"ORA-00933: SQL command not properly ended"
        )
        self.assertIn("oracle", result["database_families"])

    def test_handles_malformed_response_content(self):
        for body in (None, 123, [], {}):
            with self.subTest(body=body):
                result = detect_sql_error_indicators(body)
                self.assertEqual(result["status"], "not_detected")
                self.assertFalse(result["verified"])

    def test_only_returns_bounded_matched_evidence(self):
        body = "A" * 1000 + " ORA-00933 " + "B" * 1000
        result = detect_sql_error_indicators(body)
        self.assertEqual(len(result["indicators"]), 1)
        self.assertLessEqual(len(result["indicators"][0]["evidence"]), 200)
        self.assertNotIn(body, str(result))



class ReflectedInputDetectionTests(unittest.TestCase):
    def test_detects_exact_marker_in_text_response(self):
        result = detect_reflected_input(
            "<html><body>Search result: SMGRCmarker123</body></html>",
            "SMGRCmarker123",
        )
        self.assertEqual(result["status"], "suspected")
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["occurrences"], 1)
        self.assertIn("SMGRCmarker123", result["evidence"][0]["context"])
        self.assertFalse(result["verified"])

    def test_classifies_html_reflection_contexts(self):
        cases = (
            ("<p>SMGRCmarker123</p>", "html_text"),
            ('<input value="SMGRCmarker123">', "html_attribute"),
            ("<script>const value = 'SMGRCmarker123';</script>", "script"),
            ("<style>.SMGRCmarker123 { color: red; }</style>", "style"),
        )

        for body, expected_context in cases:
            with self.subTest(expected_context=expected_context):
                result = detect_reflected_input(body, "SMGRCmarker123")
                self.assertIn(expected_context, result["contexts"])
                self.assertFalse(result["verified"])

    def test_classifies_url_attribute_reflection_separately(self):
        cases = (
            ('<a href="/search?q=SMGRCmarker123">Open</a>', "html_url_attribute"),
            ('<img src="/SMGRCmarker123.png">', "html_url_attribute"),
            ('<form action="/SMGRCmarker123">', "html_url_attribute"),
            ('<input value="SMGRCmarker123">', "html_attribute"),
        )

        for body, expected_context in cases:
            with self.subTest(expected_context=expected_context, body=body):
                result = detect_reflected_input(body, "SMGRCmarker123")
                self.assertIn(expected_context, result["contexts"])
                self.assertFalse(result["verified"])

    def test_classifies_marker_in_html_comment_as_other(self):
        result = detect_reflected_input(
            "<!-- SMGRCmarker123 -->",
            "SMGRCmarker123",
        )
        self.assertIn("other", result["contexts"])
        self.assertFalse(result["verified"])

    def test_classifies_plain_text_reflection_as_other(self):
        result = detect_reflected_input(
            "SMGRCmarker123",
            "SMGRCmarker123",
        )
        self.assertIn("other", result["contexts"])

    def test_detects_marker_in_byte_response(self):
        result = detect_reflected_input(
            b"Response contains SMGRCmarker123",
            "SMGRCmarker123",
        )
        self.assertEqual(result["occurrences"], 1)
        self.assertFalse(result["verified"])

    def test_clean_response_has_no_reflection(self):
        result = detect_reflected_input(
            "Welcome to the application.",
            "SMGRCmarker123",
        )
        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["confidence"], "none")
        self.assertEqual(result["occurrences"], 0)
        self.assertEqual(result["evidence"], [])

    def test_truncated_response_is_inconclusive(self):
        result = detect_reflected_input(
            "SMGRCmarker123",
            "SMGRCmarker123",
            truncated=True,
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["confidence"], "none")
        self.assertEqual(result["evidence"], [])
        self.assertFalse(result["verified"])

    def test_rejects_invalid_markers(self):
        for marker in ("", "marker with spaces", "<script>", "é", "a" * 129, None):
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    detect_reflected_input("response", marker)

    def test_limits_occurrences_and_evidence_context(self):
        marker = "SMGRCmarker123"
        body = ("A" * 100 + marker) * 30
        result = detect_reflected_input(body, marker)

        self.assertEqual(result["occurrences"], 20)
        self.assertEqual(len(result["evidence"]), 20)
        self.assertTrue(
            all(len(item["context"]) <= 60 + len(marker) + 60
                for item in result["evidence"])
        )

    def test_ignores_non_text_response_content(self):
        result = detect_reflected_input(
            {"body": "SMGRCmarker123"},
            "SMGRCmarker123",
        )
        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["occurrences"], 0)


class ReflectedInputExecutionTests(unittest.TestCase):
    def setUp(self):
        self.pinned_adapters = []
        self._pinned_request_patcher = patch(
            "scanner.web_app_assessment._send_pinned_request",
            side_effect=self._mock_pinned_request,
        )
        self.mock_pinned_request = self._pinned_request_patcher.start()

    def tearDown(self):
        self._pinned_request_patcher.stop()
        for adapter in self.pinned_adapters:
            adapter.close.assert_called_once()

    def _mock_pinned_request(self, session, method, url, **kwargs):
        response = session.request(
            method,
            url,
            params=kwargs.get("params"),
            data=kwargs.get("data"),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        adapter = Mock()
        self.pinned_adapters.append(adapter)
        return response, adapter

    def _approved_scope(self):
        return {
            "id": 1,
            "status": "Approved",
            "target": "http://127.0.0.1/app",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "ports_json": "[]",
            "paths_json": '["/app/admin"]',
            "excluded_paths_json": '["/app/admin/private"]',
            "profiles_json": '["standard"]',
            "techniques_json": '["xss"]',
            "max_requests": 10,
            "rate_limit_rps": 100000,
        }

    def _check(self, **overrides):
        check = {
            "category": "xss",
            "parameter": "search",
            "location": "http://127.0.0.1/app/admin?search=old",
            "method": "GET",
            "probe": "unique_reflection_marker",
            "status": "not_tested",
            "confidence": "none",
            "verified": False,
        }
        check.update(overrides)
        return check

    @patch("scanner.web_app_assessment._validate_assessment_url")
    @patch("scanner.web_app_assessment.secrets.token_hex", return_value="abcdef0123456789")
    def test_executes_approved_get_check_and_detects_reflection(
        self, token_hex, validate_url
    ):
        validate_url.side_effect = lambda value: value
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.iter_content.return_value = iter([
            b"Search result: SMGRC_REFLECT_abcdef0123456789"
        ])
        session = Mock()
        session.request.return_value = response

        result = run_reflected_input_checks(
            [self._check()],
            session=session,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["checks"][0]["status"], "suspected")
        self.assertEqual(result["checks"][0]["confidence"], "low")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertEqual(result["requests_used"], 1)
        self.assertEqual(session.request.call_args.args[0], "GET")
        self.assertIn(
            "SMGRC_REFLECT_abcdef0123456789",
            session.request.call_args.args[1],
        )
        response.close.assert_called_once()
        token_hex.assert_called_once_with(8)

    @patch("scanner.web_app_assessment._validate_assessment_url")
    @patch("scanner.web_app_assessment.secrets.token_hex", return_value="abcdef0123456789")
    def test_clean_response_is_not_detected(self, token_hex, validate_url):
        validate_url.side_effect = lambda value: value
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.iter_content.return_value = iter([b"Welcome"])
        session = Mock()
        session.request.return_value = response

        result = run_reflected_input_checks(
            [self._check()],
            session=session,
        )

        self.assertEqual(result["checks"][0]["status"], "not_detected")
        self.assertEqual(result["checks"][0]["occurrences"], 0)

    @patch("scanner.web_app_assessment._validate_assessment_url")
    @patch("scanner.web_app_assessment.secrets.token_hex", return_value="abcdef0123456789")
    def test_truncated_response_is_inconclusive(self, token_hex, validate_url):
        validate_url.side_effect = lambda value: value
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.iter_content.return_value = iter([b"Partial response"])
        session = Mock()
        session.request.return_value = response

        with patch(
            "scanner.web_app_assessment._assessment_request",
            return_value={
                "url": "http://127.0.0.1/app/admin",
                "status_code": 200,
                "body": b"SMGRC_REFLECT_abcdef0123456789",
                "truncated": True,
            },
        ):
            result = run_reflected_input_checks(
                [self._check()],
                    session=session,
            )

        self.assertEqual(result["checks"][0]["status"], "inconclusive")
        self.assertFalse(result["checks"][0]["verified"])

    @patch("scanner.web_app_assessment._assessment_request")
    def test_budget_exhaustion_returns_not_tested(self, assessment_request):
        assessment_request.side_effect = WebAssessmentRequestError(
            "Request budget exhausted."
        )
        session = Mock()
        budget = AssessmentRequestBudget(
            maximum=1, profile="standard"
        )

        result = run_reflected_input_checks(
            [self._check()],
            session=session,
            budget=budget,
        )

        check = result["checks"][0]
        self.assertEqual(check["status"], "not_tested")
        self.assertEqual(check["confidence"], "none")
        self.assertFalse(check["verified"])
        self.assertEqual(check["evidence"], [])
        self.assertEqual(result["requests_used"], 0)
        self.assertEqual(result["requests_remaining"], 1)

    def test_does_not_require_approved_scope_list(self):
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.iter_content.return_value = iter([b"Welcome"])

        session = Mock()
        session.request.return_value = response

        result = run_reflected_input_checks(
            [self._check()],
            session=session,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["checks"][0]["status"], "not_detected")
        self.assertEqual(result["requests_used"], 1)

    def test_rejects_non_get_or_unrecognized_checks(self):
        session = Mock()

        for overrides in (
            {"method": "POST"},
            {"probe": "script_payload"},
            {"status": "completed"},
            {"verified": True},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(WebAssessmentRequestError):
                    run_reflected_input_checks(
                        [self._check(**overrides)],
                                    session=session,
                    )

        session.request.assert_not_called()

    def test_rejects_budget_profile_mismatch(self):
        session = Mock()
        budget = AssessmentRequestBudget(profile="comprehensive")

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "does not match"
        ):
            run_reflected_input_checks(
                [self._check()],
                    profile="standard",
                session=session,
                budget=budget,
            )

        session.request.assert_not_called()

    def test_sensitive_parameter_is_rejected(self):
        session = Mock()

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "not eligible"
        ):
            run_reflected_input_checks(
                [self._check(parameter="password")],
                    session=session,
            )

        session.request.assert_not_called()


class ResponseBaselineTests(unittest.TestCase):
    def test_identical_responses_produce_identical_fingerprints(self):
        response = {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": b"<title>Welcome</title><p>Home</p>",
            "truncated": False,
        }

        first = build_response_baseline(response)
        second = build_response_baseline(response)

        self.assertEqual(first["body_sha256"], second["body_sha256"])
        self.assertEqual(first["title_sha256"], second["title_sha256"])

    def test_changed_body_produces_different_fingerprint(self):
        first = build_response_baseline({
            "status_code": 200,
            "headers": {},
            "body": b"First response",
        })
        second = build_response_baseline({
            "status_code": 200,
            "headers": {},
            "body": b"Different response",
        })

        self.assertNotEqual(first["body_sha256"], second["body_sha256"])

    def test_captures_status_and_content_type(self):
        result = build_response_baseline({
            "status_code": 403,
            "headers": {"content-type": "application/json"},
            "body": b'{"error":"forbidden"}',
        })

        self.assertEqual(result["status_code"], 403)
        self.assertEqual(result["content_type"], "application/json")
        self.assertEqual(result["body_length"], 21)

    def test_truncated_response_is_incomplete(self):
        result = build_response_baseline({
            "status_code": 200,
            "headers": {},
            "body": b"partial response",
            "truncated": True,
        })

        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])

    def test_rejects_invalid_response_structure(self):
        invalid_responses = [
            None,
            [],
            {},
            {"status_code": 99},
            {"status_code": 600},
            {"status_code": "200"},
        ]

        for response in invalid_responses:
            with self.subTest(response=response):
                with self.assertRaises(ValueError):
                    build_response_baseline(response)


class SQLResponseComparisonTests(unittest.TestCase):
    def _response(self, body, status=200, truncated=False):
        return {
            "status_code": status,
            "headers": {"content-type": "text/html"},
            "body": body,
            "truncated": truncated,
        }

    def test_identical_responses_are_not_detected(self):
        response = self._response(b"<title>Home</title><p>Welcome</p>")
        result = compare_sql_responses(response, response)

        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["differences"], [])
        self.assertFalse(result["verified"])

    def test_dynamic_timestamp_does_not_change_normalized_fingerprint(self):
        baseline = self._response(
            b"<html><p>Welcome</p><time>2026-11-12T10:00:00Z</time></html>"
        )
        tested = self._response(
            b"<html><p>Welcome</p><time>2026-11-12T10:05:00Z</time></html>"
        )

        baseline_result = build_response_baseline(baseline)
        tested_result = build_response_baseline(tested)

        self.assertNotEqual(
            baseline_result["body_sha256"],
            tested_result["body_sha256"],
        )
        self.assertIn("normalized_body_sha256", baseline_result)
        self.assertEqual(
            baseline_result["normalized_body_sha256"],
            tested_result["normalized_body_sha256"],
        )

    def test_timestamp_only_change_is_not_a_meaningful_body_change(self):
        baseline = self._response(
            b"<html><p>Welcome</p><time>2026-11-12T10:00:00Z</time></html>"
        )
        tested = self._response(
            b"<html><p>Welcome</p><time>2026-11-12T10:05:00Z</time></html>"
        )

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "not_detected")
        self.assertNotIn("response_body_changed", result["differences"])
        self.assertNotIn("response_length_changed", result["differences"])
        self.assertNotEqual(
            result["baseline"]["body_sha256"],
            result["test"]["body_sha256"],
        )
        self.assertEqual(
            result["baseline"]["normalized_body_sha256"],
            result["test"]["normalized_body_sha256"],
        )
        self.assertFalse(result["verified"])

    def test_normalized_fingerprint_preserves_meaningful_content_changes(self):
        baseline = self._response(b"<html><p>Welcome</p></html>")
        tested = self._response(b"<html><p>Access denied</p></html>")

        baseline_result = build_response_baseline(baseline)
        tested_result = build_response_baseline(tested)

        self.assertNotEqual(
            baseline_result["normalized_body_sha256"],
            tested_result["normalized_body_sha256"],
        )

    def test_http_status_change_is_inconclusive(self):
        baseline = self._response(b"Welcome", status=200)
        tested = self._response(b"Forbidden", status=403)

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("http_status_changed", result["differences"])
        self.assertFalse(result["verified"])

    def test_body_and_length_changes_are_inconclusive(self):
        baseline = self._response(b"Normal response")
        tested = self._response(b"Different response body")

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("response_body_changed", result["differences"])
        self.assertIn("response_length_changed", result["differences"])
        self.assertNotEqual(result["body_length_delta"], 0)
        self.assertFalse(result["verified"])

    def test_database_error_indicator_is_suspected(self):
        baseline = self._response(b"Normal application response")
        tested = self._response(
            b"ORA-00933: SQL command not properly ended"
        )

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "suspected")
        self.assertIn(
            "database_error_indicator_detected", result["differences"]
        )
        self.assertTrue(result["database_error_indicators"])
        self.assertFalse(result["verified"])

    def test_preexisting_database_error_is_not_new_evidence(self):
        baseline = self._response(
            b"ORA-00933: SQL command not properly ended"
        )
        tested = self._response(
            b"ORA-00933: SQL command not properly ended"
        )

        result = compare_sql_responses(baseline, tested)

        self.assertNotEqual(result["status"], "suspected")
        self.assertNotIn(
            "database_error_indicator_detected", result["differences"]
        )
        self.assertFalse(result["verified"])

    def test_same_database_indicator_with_changed_evidence_is_not_new(self):
        baseline = self._response(b"near 'id': syntax error")
        tested = self._response(b"near 'name': syntax error")

        result = compare_sql_responses(baseline, tested)

        self.assertNotEqual(result["status"], "suspected")
        self.assertNotIn(
            "database_error_indicator_detected", result["differences"]
        )
        self.assertFalse(result["database_error_indicators"])
        self.assertFalse(result["verified"])

    def test_new_database_error_remains_suspected(self):
        baseline = self._response(b"Normal application response")
        tested = self._response(
            b"ORA-00933: SQL command not properly ended"
        )

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "suspected")
        self.assertIn(
            "database_error_indicator_detected", result["differences"]
        )
        self.assertTrue(result["database_error_indicators"])
        self.assertFalse(result["verified"])

    def test_truncated_response_makes_comparison_inconclusive(self):
        baseline = self._response(b"Normal response")
        tested = self._response(b"Partial response", truncated=True)

        result = compare_sql_responses(baseline, tested)

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["confidence"], "none")
        self.assertIn("truncated", result["reason"])
        self.assertFalse(result["verified"])

    def test_comparison_never_claims_vulnerability_verification(self):
        baseline = self._response(b"Normal response")
        tested = self._response(
            b"You have an error in your SQL syntax"
        )

        result = compare_sql_responses(baseline, tested)

        self.assertFalse(result["verified"])
        self.assertIn(
            "Manual or independent verification",
            " ".join(result["notes"]),
        )


class BooleanSQLResponseComparisonTests(unittest.TestCase):
    def _response(self, body, status=200, content_type="text/html",
                  truncated=False):
        return {
            "status_code": status,
            "headers": {"content-type": content_type},
            "body": body,
            "truncated": truncated,
        }

    def test_identical_true_and_false_responses_are_not_detected(self):
        response = self._response(b"<p>Welcome</p>")

        result = compare_boolean_sql_responses(response, response)

        self.assertEqual(result["status"], "not_detected")
        self.assertEqual(result["differences"], [])
        self.assertFalse(result["verified"])

    def test_meaningful_body_difference_is_only_suspected(self):
        true_response = self._response(
            b"<p>Account found</p>"
        )
        false_response = self._response(
            b"<p>No account found</p>"
        )

        result = compare_boolean_sql_responses(
            true_response, false_response
        )

        self.assertEqual(result["status"], "suspected")
        self.assertEqual(result["confidence"], "low")
        self.assertIn("response_body_changed", result["differences"])
        self.assertFalse(result["verified"])

    def test_http_status_difference_is_inconclusive(self):
        true_response = self._response(b"Welcome", status=200)
        false_response = self._response(b"Forbidden", status=403)

        result = compare_boolean_sql_responses(
            true_response, false_response
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("http_status_changed", result["differences"])
        self.assertFalse(result["verified"])

    def test_content_type_difference_is_inconclusive(self):
        true_response = self._response(
            b'{"result":true}', content_type="application/json"
        )
        false_response = self._response(
            b"<p>False</p>", content_type="text/html"
        )

        result = compare_boolean_sql_responses(
            true_response, false_response
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("content_type_changed", result["differences"])
        self.assertFalse(result["verified"])

    def test_truncated_response_is_inconclusive(self):
        true_response = self._response(b"Complete")
        false_response = self._response(
            b"Partial", truncated=True
        )

        result = compare_boolean_sql_responses(
            true_response, false_response
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["confidence"], "none")
        self.assertFalse(result["verified"])

    def test_comparison_does_not_retain_response_bodies(self):
        true_response = self._response(b"Sensitive true response")
        false_response = self._response(b"Sensitive false response")

        result = compare_boolean_sql_responses(
            true_response, false_response
        )

        serialized = json.dumps(result)
        self.assertNotIn("Sensitive true response", serialized)
        self.assertNotIn("Sensitive false response", serialized)
        self.assertFalse(result["verified"])


class QueryParameterMutationTests(unittest.TestCase):
    def _candidate(self, url, parameter="id", **overrides):
        candidate = {
            "category": "sql_injection",
            "parameter": parameter,
            "source": "query",
            "location": url,
            "replay_eligible": True,
        }
        candidate.update(overrides)
        return candidate

    def test_replaces_only_selected_duplicate_parameter(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?id=first&id=second&sort=name"
        )
        result = _mutate_query_parameter(
            candidate, "sql_injection", "replacement", occurrence=1
        )
        self.assertEqual(
            result,
            "http://127.0.0.1/search?id=first&id=replacement&sort=name",
        )

    def test_preserves_unrelated_query_parameters(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?q=original&page=2&empty=",
            parameter="q",
        )
        result = _mutate_query_parameter(
            candidate, "sql_injection", "changed value"
        )
        self.assertEqual(
            result,
            "http://127.0.0.1/search?q=changed+value&page=2&empty=",
        )

    def test_rejects_ineligible_or_mismatched_candidates(self):
        cases = (
            {"replay_eligible": False},
            {"replay_eligible": 1},
            {"source": "form"},
            {"category": "authentication_session"},
            {"parameter": "password"},
            {"parameter": "username"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                candidate = self._candidate(
                    "http://127.0.0.1/search?id=first",
                    **overrides,
                )
                with self.assertRaises(WebAssessmentRequestError):
                    _mutate_query_parameter(
                        candidate, "sql_injection", "replacement"
                    )

    def test_command_injection_candidate_cannot_be_replayed(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?cmd=status",
            parameter="cmd",
        )
        candidate["category"] = "command_injection"
        candidate["replay_eligible"] = True

        with self.assertRaises(WebAssessmentRequestError):
            _mutate_query_parameter(
                candidate,
                "command_injection",
                "ping-test",
            )

    def test_rejects_missing_occurrences_and_invalid_indexes(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?id=first"
        )
        for occurrence in (1, -1, True, 1.5, "0"):
            with self.subTest(occurrence=occurrence):
                with self.assertRaises(WebAssessmentRequestError):
                    _mutate_query_parameter(
                        candidate, "sql_injection", "replacement",
                        occurrence=occurrence,
                    )

    def test_boolean_sql_category_can_mutate_eligible_query_parameter(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?id=original"
        )
        candidate["category"] = "sql_boolean_based"

        result = _mutate_query_parameter(
            candidate,
            "sql_boolean_based",
            "boolean-test",
        )

        self.assertEqual(
            result,
            "http://127.0.0.1/search?id=boolean-test",
        )

    def test_boolean_sql_category_keeps_sensitive_parameter_protection(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?token=original",
            parameter="token",
        )
        candidate["category"] = "sql_boolean_based"

        with self.assertRaises(WebAssessmentRequestError):
            _mutate_query_parameter(
                candidate,
                "sql_boolean_based",
                "boolean-test",
            )

    def test_rejects_category_mismatch_and_invalid_candidate(self):
        candidate = self._candidate(
            "http://127.0.0.1/search?id=first"
        )
        with self.assertRaises(WebAssessmentRequestError):
            _mutate_query_parameter(candidate, "xss", "replacement")

        with self.assertRaises(WebAssessmentRequestError):
            _mutate_query_parameter(
                None, "sql_injection", "replacement"
            )



class SQLInjectionExecutionTests(unittest.TestCase):
    def _approved_scope(self, **overrides):
        scope = {
            "id": 2,
            "status": "Approved",
            "target": "http://127.0.0.1/app",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "ports_json": "[]",
            "paths_json": '["/app/admin"]',
            "excluded_paths_json": '["/app/admin/private"]',
            "profiles_json": '["standard"]',
            "techniques_json": '["sql_injection"]',
            "max_requests": 10,
            "rate_limit_rps": 100000,
        }
        scope.update(overrides)
        return scope

    def _check(self, **overrides):
        check = {
            "category": "sql_injection",
            "parameter": "id",
            "location": "http://127.0.0.1/app/admin?id=10",
            "method": "GET",
            "probe": "single_quote",
            "status": "not_tested",
            "confidence": "none",
            "verified": False,
        }
        check.update(overrides)
        return check

    @patch("scanner.web_app_assessment._assessment_request")
    def test_executes_baseline_and_single_quote_get_pair(
        self, assessment_request
    ):
        response = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": b"Welcome",
            "truncated": False,
        }
        def simulate_assessment_request(*args, **kwargs):
            kwargs["budget"].consume()
            return response

        assessment_request.side_effect = simulate_assessment_request

        session = Mock()
        result = run_sql_injection_checks(
            [self._check()],
            session=session,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["requests_used"], 2)
        self.assertEqual(result["requests_remaining"], 48)
        self.assertEqual(result["checks"][0]["status"], "not_detected")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertEqual(assessment_request.call_count, 2)

        first_call, second_call = assessment_request.call_args_list
        self.assertEqual(first_call.args[1], "GET")
        self.assertEqual(
            first_call.args[2],
            "http://127.0.0.1/app/admin?id=10",
        )
        self.assertEqual(second_call.args[1], "GET")
        self.assertEqual(
            second_call.args[2],
            "http://127.0.0.1/app/admin?id=%27",
        )

    @patch("scanner.web_app_assessment._assessment_request")
    def test_database_error_indicator_is_suspected_not_verified(
        self, assessment_request
    ):
        baseline = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Welcome",
            "truncated": False,
        }
        tested = {
            "url": "http://127.0.0.1/app/admin?id=%27",
            "status_code": 500,
            "headers": {},
            "body": b"You have an error in your SQL syntax",
            "truncated": False,
        }
        assessment_request.side_effect = [baseline, tested]

        result = run_sql_injection_checks(
            [self._check()],
            session=Mock(),
        )

        self.assertEqual(result["checks"][0]["status"], "suspected")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertTrue(
            result["checks"][0]["database_error_indicators"]
        )
        self.assertEqual(result["verified_vulnerabilities"], 0)


    @patch("scanner.web_app_assessment._assessment_request")
    @patch("scanner.web_app_assessment.requests.Session")
    def test_runner_closes_internally_created_session(
        self, session_factory, assessment_request
    ):
        session = session_factory.return_value
        response = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Welcome",
            "truncated": False,
        }
        assessment_request.side_effect = [response, response]

        result = run_sql_injection_checks(
            [self._check()],
        )

        self.assertEqual(result["status"], "completed")
        session.close.assert_called_once_with()

    @patch("scanner.web_app_assessment._assessment_request")
    @patch("scanner.web_app_assessment.requests.Session")
    def test_runner_closes_internal_session_when_request_fails(
        self, session_factory, assessment_request
    ):
        session = session_factory.return_value
        assessment_request.side_effect = WebAssessmentRequestError(
            "Simulated request failure."
        )

        with self.assertRaisesRegex(
            WebAssessmentRequestError, "Simulated request failure"
        ):
            run_sql_injection_checks(
                [self._check()],
                )

        session.close.assert_called_once_with()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_runner_does_not_close_caller_supplied_session(
        self, assessment_request
    ):
        response = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Welcome",
            "truncated": False,
        }
        assessment_request.side_effect = [response, response]
        session = Mock()

        result = run_sql_injection_checks(
            [self._check()],
            session=session,
        )

        self.assertEqual(result["status"], "completed")
        session.close.assert_not_called()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_sensitive_parameter_is_rejected_before_http_request(
        self, assessment_request
    ):
        with self.assertRaises(WebAssessmentRequestError):
            run_sql_injection_checks(
                [
                    self._check(
                        parameter="password",
                        location=(
                            "http://127.0.0.1/app/admin?password=example"
                        ),
                    )
                ],
                    session=Mock(),
            )

        assessment_request.assert_not_called()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_post_method_is_rejected_before_http_request(
        self, assessment_request
    ):
        with self.assertRaises(WebAssessmentRequestError):
            run_sql_injection_checks(
                [self._check(method="POST")],
                    session=Mock(),
            )

        assessment_request.assert_not_called()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_unsupported_probe_is_rejected_before_http_request(
        self, assessment_request
    ):
        with self.assertRaises(WebAssessmentRequestError):
            run_sql_injection_checks(
                [self._check(probe="time_delay")],
                    session=Mock(),
            )

        assessment_request.assert_not_called()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_insufficient_global_budget_sends_no_requests(
        self, assessment_request
    ):
        budget = AssessmentRequestBudget(maximum=1, profile="standard")

        result = run_sql_injection_checks(
            [self._check()],
            session=Mock(),
            budget=budget,
        )

        self.assertEqual(result["checks"][0]["status"], "not_tested")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertEqual(result["requests_used"], 0)
        assessment_request.assert_not_called()

    @patch("scanner.web_app_assessment._assessment_request")
    def test_budget_exhaustion_during_request_pair_returns_not_tested(
        self, assessment_request
    ):
        budget = AssessmentRequestBudget(maximum=2, profile="standard")
        baseline = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Welcome",
            "truncated": False,
        }

        def simulate_redirect_budget(*args, **kwargs):
            request_budget = kwargs["budget"]
            request_budget.consume()

            if assessment_request.call_count == 2:
                request_budget.consume()

            return baseline

        assessment_request.side_effect = simulate_redirect_budget

        result = run_sql_injection_checks(
            [self._check()],
            session=Mock(),
            budget=budget,
        )

        check = result["checks"][0]
        self.assertEqual(check["status"], "not_tested")
        self.assertFalse(check["verified"])
        self.assertEqual(result["requests_used"], 2)
        self.assertEqual(result["requests_remaining"], 0)
        self.assertEqual(assessment_request.call_count, 2)


    @patch("scanner.web_app_assessment._assessment_request")
    def test_truncated_response_is_inconclusive(
        self, assessment_request
    ):
        baseline = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Partial",
            "truncated": True,
        }
        tested = {
            "url": "http://127.0.0.1/app/admin?id=%27",
            "status_code": 200,
            "headers": {},
            "body": b"Partial",
            "truncated": False,
        }
        assessment_request.side_effect = [baseline, tested]

        result = run_sql_injection_checks(
            [self._check()],
            session=Mock(),
        )

        self.assertEqual(result["checks"][0]["status"], "inconclusive")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertEqual(assessment_request.call_count, 2)

    @patch("scanner.web_app_assessment._assessment_request")
    def test_response_difference_without_database_error_is_inconclusive(
        self, assessment_request
    ):
        baseline = {
            "url": "http://127.0.0.1/app/admin?id=10",
            "status_code": 200,
            "headers": {},
            "body": b"Welcome",
            "truncated": False,
        }
        tested = {
            "url": "http://127.0.0.1/app/admin?id=%27",
            "status_code": 500,
            "headers": {},
            "body": b"An unexpected application error occurred",
            "truncated": False,
        }
        assessment_request.side_effect = [baseline, tested]

        result = run_sql_injection_checks(
            [self._check()],
            session=Mock(),
        )

        self.assertEqual(result["checks"][0]["status"], "inconclusive")
        self.assertFalse(result["checks"][0]["verified"])
        self.assertEqual(
            result["checks"][0]["database_error_indicators"], []
        )




class AssessmentTargetNormalizationTests(unittest.TestCase):
    def test_normalizes_bare_hostname_and_url(self):
        self.assertEqual(
            normalize_assessment_target("Example.COM."),
            "http://example.com/",
        )
        self.assertEqual(
            normalize_assessment_target("https://Example.COM:8443/app?q=1"),
            "https://example.com:8443/app?q=1",
        )

    def test_normalizes_ipv4_and_ipv6_targets(self):
        self.assertEqual(
            normalize_assessment_target("192.168.1.10"),
            "http://192.168.1.10/",
        )
        self.assertEqual(
            normalize_assessment_target("https://[2001:db8::1]:8443/"),
            "https://[2001:db8::1]:8443/",
        )

    def test_rejects_credentials_fragments_and_invalid_ports(self):
        invalid_targets = (
            "https://user:pass@example.com/",
            "https://example.com/#fragment",
            "http://example.com:0/",
            "http://example.com:65536/",
            "ftp://example.com/",
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(AssessmentTargetValidationError):
                    normalize_assessment_target(target)

    def test_rejects_malformed_hostnames(self):
        invalid_targets = (
            "http://bad host/",
            "http://-invalid.example/",
            "http://invalid..example/",
            "http://example.com:abc/",
            "",
            None,
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(AssessmentTargetValidationError):
                    normalize_assessment_target(target)

    @patch("scanner.web_app_assessment.socket.getaddrinfo")
    def test_does_not_resolve_hostnames_during_normalization(self, resolve):
        result = normalize_assessment_target("internal.example")
        self.assertEqual(result, "http://internal.example/")
        resolve.assert_not_called()


class AssessmentRequestBudgetTests(unittest.TestCase):
    def test_tracks_request_usage_and_remaining_capacity(self):
        budget = AssessmentRequestBudget(maximum=3)

        self.assertEqual(budget.used, 0)
        self.assertEqual(budget.remaining, 3)

        budget.consume()

        self.assertEqual(budget.used, 1)
        self.assertEqual(budget.remaining, 2)

    def test_rejects_requests_after_budget_is_exhausted(self):
        budget = AssessmentRequestBudget(maximum=1)
        budget.consume()

        with self.assertRaises(WebAssessmentRequestError):
            budget.consume()

        self.assertEqual(budget.used, 1)
        self.assertEqual(budget.remaining, 0)

    def test_rejects_invalid_budget_limits(self):
        for value in (0, -1, True, 1.5, "5"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    AssessmentRequestBudget(maximum=value)


if __name__ == "__main__":
    unittest.main()
