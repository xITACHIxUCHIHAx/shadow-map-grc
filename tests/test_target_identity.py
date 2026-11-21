import unittest

from target_identity import (
    group_targets,
    target_group_key,
    target_group_label,
)


class TargetIdentityTests(unittest.TestCase):
    def test_paths_and_queries_group_under_same_origin(self):
        targets = [
            "https://vhnsnc.edu.in/",
            "https://vhnsnc.edu.in/index.php",
            "https://vhnsnc.edu.in/page.php?page=admission",
        ]

        groups = group_targets(targets)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["label"], "https://vhnsnc.edu.in")
        self.assertEqual(set(groups[0]["targets"]), set(targets))

    def test_default_ports_are_normalized(self):
        self.assertEqual(
            target_group_key("https://example.test:443/path"),
            target_group_key("https://example.test/other"),
        )
        self.assertEqual(
            target_group_key("http://example.test:80/path"),
            target_group_key("http://example.test/other"),
        )

    def test_non_default_ports_remain_separate(self):
        self.assertNotEqual(
            target_group_key("https://example.test/path"),
            target_group_key("https://example.test:8443/path"),
        )

    def test_scheme_and_subdomain_remain_separate(self):
        base = target_group_key("https://example.test/path")

        self.assertNotEqual(
            base, target_group_key("http://example.test/path")
        )
        self.assertNotEqual(
            base, target_group_key("https://www.example.test/path")
        )

    def test_ip_targets_remain_separate_from_web_origins(self):
        self.assertNotEqual(
            target_group_key("192.0.2.10"),
            target_group_key("http://192.0.2.10/"),
        )

    def test_non_url_targets_are_case_insensitive_but_distinct(self):
        self.assertEqual(
            target_group_key("Server-01"),
            target_group_key("server-01"),
        )
        self.assertNotEqual(
            target_group_key("192.0.2.10"),
            target_group_key("192.0.2.11"),
        )

    def test_label_excludes_path_and_default_port(self):
        self.assertEqual(
            target_group_label("https://EXAMPLE.test:443/a?q=1"),
            "https://example.test",
        )

    def test_non_default_port_is_shown_in_label(self):
        self.assertEqual(
            target_group_label("https://example.test:8443/a"),
            "https://example.test:8443",
        )

    def test_empty_target_is_ignored_by_grouping(self):
        self.assertEqual(group_targets(["", None, "  "]), [])


if __name__ == "__main__":
    unittest.main()
