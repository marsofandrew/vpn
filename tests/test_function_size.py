import json
import unittest
from pathlib import Path

from scripts.check_function_size import Finding, scan_project, scan_source, violations


class FunctionSizeTests(unittest.TestCase):
    def test_physical_lines_include_signature_docstring_and_blanks(self):
        source = '@decorator\ndef sample(\n    value,\n):\n    """Docstring.\n    More.\n    """\n\n    return value\n'
        (finding,) = scan_source(source, "sample.py")
        self.assertEqual((finding.line, finding.size), (2, 8))

    def test_classes_nested_async_functions_and_lambdas_are_scanned(self):
        source = "class A:\n    async def run(self):\n        def nested():\n            return lambda: (\n                1\n            )\n        return nested()\n"
        findings = scan_source(source, "sample.py")
        self.assertEqual(
            [f.name for f in findings],
            ["A.run", "A.run.nested", "A.run.nested.<lambda>@4"],
        )
        self.assertEqual([f.size for f in findings], [6, 4, 3])

    def test_hard_limit_has_no_justification_exception(self):
        finding = Finding("sample.py", "sample", 1, 61)
        errors = violations([finding], {finding.key: "Cannot waive the hard limit."})
        self.assertTrue(any("hard limit 60" in error for error in errors))

    def test_preferred_range_requires_reason_and_obsolete_reasons_fail(self):
        finding = Finding("sample.py", "sample", 1, 60)
        self.assertEqual(
            violations([finding], {finding.key: "One ordered transaction."}), []
        )
        self.assertIn("missing cohesion justification", violations([finding], {})[0])
        self.assertIn(
            "stale justification", violations([], {finding.key: "Obsolete."})[0]
        )

    def test_exact_physical_boundary(self):
        for size in (30, 60, 61):
            source = "def sample():\n" + "\n" * (size - 2) + "    return 1\n"
            (finding,) = scan_source(source, "sample.py")
            self.assertEqual(finding.size, size)
            errors = violations(
                [finding], {finding.key: "One cohesive check."} if size == 60 else {}
            )
            self.assertEqual(bool(errors), size == 61)

    def test_entire_project_stays_within_limits(self):
        root = Path(__file__).resolve().parents[1]
        reasons = json.loads(
            (root / "docs/function_size_justifications.json").read_text()
        )
        self.assertEqual(violations(scan_project(root), reasons), [])
