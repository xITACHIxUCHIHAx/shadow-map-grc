import unittest

from scanner.batch_runner import (
    parse_batch_targets,
    run_batch,
    summarize_batch,
)


class BatchTargetParsingTests(unittest.TestCase):
    def test_parses_multiline_targets_and_ignores_blank_lines(self):
        self.assertEqual(
            parse_batch_targets(
                "\nexample.com\n\n192.0.2.10\n server-01 \n"
            ),
            ["example.com", "192.0.2.10", "server-01"],
        )

    def test_rejects_empty_batch(self):
        with self.assertRaises(ValueError):
            parse_batch_targets("\n  \n")

    def test_rejects_duplicate_targets_case_insensitively(self):
        with self.assertRaises(ValueError):
            parse_batch_targets("Example.com\nexample.com")

    def test_enforces_batch_limit(self):
        with self.assertRaises(ValueError):
            parse_batch_targets(
                "\n".join(f"host-{i}.example" for i in range(26))
            )


class BatchExecutionTests(unittest.TestCase):
    def test_failure_does_not_stop_later_targets(self):
        calls = []

        def validator(target):
            if target == "bad":
                raise ValueError("Rejected target")
            return target

        def scanner(target):
            calls.append(target)
            if target == "timeout":
                raise TimeoutError("Scan timed out")
            return {"status": "Completed", "target": target}

        results = run_batch(
            ["bad", "good", "timeout", "later"],
            validator,
            scanner,
        )

        self.assertEqual(
            [item.status for item in results],
            ["Failed", "Completed", "Failed", "Completed"],
        )
        self.assertEqual(calls, ["good", "timeout", "later"])
        self.assertEqual(results[0].error, "Rejected target")
        self.assertEqual(results[2].error, "Scan timed out")

    def test_preserves_partial_scan_status(self):
        results = run_batch(
            ["host"],
            lambda target: target,
            lambda target: {"status": "Partial"},
        )
        self.assertEqual(results[0].status, "Partial")

    def test_summary_counts_all_outcomes(self):
        results = run_batch(
            ["one", "two", "three"],
            lambda target: target,
            lambda target: (
                {"status": "Partial"}
                if target == "two"
                else {"status": "Completed"}
            ),
        )

        results[2].status = "Failed"

        self.assertEqual(
            summarize_batch(results),
            {
                "status": "Partial",
                "total_targets": 3,
                "completed_targets": 1,
                "partial_targets": 1,
                "failed_targets": 1,
            },
        )

    def test_all_failed_batch_is_failed(self):
        results = run_batch(
            ["one"],
            lambda target: (_ for _ in ()).throw(ValueError("invalid")),
            lambda target: {},
        )
        self.assertEqual(summarize_batch(results)["status"], "Failed")


if __name__ == "__main__":
    unittest.main()
