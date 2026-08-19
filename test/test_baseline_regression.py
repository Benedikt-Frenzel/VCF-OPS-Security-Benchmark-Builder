"""Baseline regression test: generated rule defaults vs. the Aria Operations export.

Ground truth is the committed fixture `test/fixtures/baseline-conditions.json`
(extracted from the sibling repository's `Alert-and-SymtomDefinitions.xml` by
`tools/extract_baseline_conditions.py`). This is the test that would have
caught the P0: before PR #16 the builder copied desired-state cells verbatim,
so e.g. `= 40.0` produced an `= 40.0` symptom that NEVER fires.

Comparison semantics are those of `tools/compare_baseline.py` (reused here by
import): a rule is aligned when its (operator, value, valueType, type) tuple
matches ANY baseline variant for that key; every other mismatch must be listed
in KNOWN_DEVIATIONS or the test fails.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "baseline-conditions.json"
CSV_PATH = REPO_ROOT / "data" / "decision-matrix.csv"

# tools/ is not a package; import both helpers from their file paths.
spec = importlib.util.spec_from_file_location("compare_baseline", REPO_ROOT / "tools" / "compare_baseline.py")
compare_baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare_baseline)

spec = importlib.util.spec_from_file_location("build_rules", REPO_ROOT / "tools" / "build_rules.py")
build_rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_rules)

spec = importlib.util.spec_from_file_location(
    "extract_baseline_conditions", REPO_ROOT / "tools" / "extract_baseline_conditions.py"
)
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


def load_fixture(path=FIXTURE_PATH):
    """Fixture JSON -> {condition_key: [(operator, value, valueType, type), ...]}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {key: [tuple(variant) for variant in variants] for key, variants in data.items()}


def derive_rules():
    """Run the builder in-process against the real matrix, return the rules list."""
    import io
    import sys
    from contextlib import redirect_stdout

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "rules.js"
        argv, cwd = sys.argv, Path.cwd()
        sys.argv = ["build_rules.py", "--csv", "data/decision-matrix.csv", "--out", str(out_path)]
        try:
            import os

            os.chdir(REPO_ROOT)
            with redirect_stdout(io.StringIO()):
                build_rules.main()
        finally:
            sys.argv = argv
            import os

            os.chdir(cwd)
        return compare_baseline.load_rules(str(out_path))


class BaselineRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = derive_rules()
        cls.baseline = load_fixture()

    def compare(self):
        """(aligned, deviations, unexplained) using compare_baseline semantics."""
        aligned, deviations, unexplained = [], [], []
        for rule in self.rules:
            key = rule["conditionKey"]
            if key not in self.baseline:
                continue
            actual = (rule["operator"], rule["value"], rule["valueType"], rule["type"])
            if actual in self.baseline[key]:
                aligned.append((key, actual))
            elif key in compare_baseline.KNOWN_DEVIATIONS:
                deviations.append((key, actual, sorted(self.baseline[key])))
            else:
                unexplained.append((key, actual, sorted(self.baseline[key])))
        return aligned, deviations, unexplained

    def test_zero_unexplained_mismatches(self):
        """Every shared condition must match a baseline variant or a documented
        deviation - this is the gate that would have failed before PR #16."""
        aligned, deviations, unexplained = self.compare()
        self.assertEqual(
            unexplained,
            [],
            "generated conditions deviate from the baseline export without an "
            "entry in tools/compare_baseline.py KNOWN_DEVIATIONS:\n"
            + "\n".join(f"  {k}: {a} not in {b}" for k, a, b in unexplained),
        )
        self.assertGreater(len(aligned), 0)
        self.assertGreater(len(deviations), 0)

    def test_every_rule_key_exists_in_baseline(self):
        rule_keys = {r["conditionKey"] for r in self.rules}
        self.assertEqual(len(self.rules), 144)
        self.assertEqual(rule_keys - set(self.baseline), set())

    def test_deviations_are_exactly_the_documented_set(self):
        """The KNOWN_DEVIATIONS list must stay tight: no stale entries, no gaps."""
        _, deviations, _ = self.compare()
        self.assertEqual(
            {key for key, _, _ in deviations}, set(compare_baseline.KNOWN_DEVIATIONS)
        )

    def test_issue1_evidence_rows_match_baseline(self):
        """The four P0 examples from issue #1, asserted against the baseline itself:
        these must be exact baseline variants (not deviations)."""
        by_key = {r["conditionKey"]: r for r in self.rules}
        expected_rows = {
            "ComplianceMetrics|APILimits|Client_API_Concurrency_Limit": ("!=", "40.0", "numeric", "property"),
            "config|boot_options_efi_secure_boot_enabled": ("=", "false", "string", "property"),
            "config|extraConfig|mem_tps_share": ("=", "true", "string", "property"),
            "security|NtpServersCount": ("<", "3.0", "numeric", "metric"),
        }
        for key, expected in expected_rows.items():
            with self.subTest(key=key):
                rule = by_key[key]
                actual = (rule["operator"], rule["value"], rule["valueType"], rule["type"])
                self.assertEqual(actual, expected)
                self.assertIn(actual, self.baseline[key])

    def test_inverted_operators_against_baseline(self):
        """Spot-check that inversion moved conditions to the opposite direction:
        for aligned numeric keys, generated operator must differ from the
        desired-state operator recorded in the matrix."""
        # '= 40.0' desired -> '!=' violation; '>= 3.0' desired -> '<' violation.
        by_key = {r["conditionKey"]: r for r in self.rules}
        desired = {
            "ComplianceMetrics|APILimits|Client_API_Concurrency_Limit": ("=", "40.0"),
            "security|NtpServersCount": ("\u2265", "3.0"),
            "ComplianceMetrics|HttpSessionTimeOut": ("=", "1800.0"),
        }
        for key, (op, value) in desired.items():
            with self.subTest(key=key):
                rule = by_key[key]
                self.assertEqual(rule["value"], value)
                self.assertNotEqual(rule["operator"], build_rules.OPERATOR_MAP[op])

    def test_fixture_is_fresh_against_local_baseline_export(self):
        """When the sibling baseline export is checked out, the committed fixture
        must match it (guards against forgetting to re-run the extractor).
        Skipped where the sibling repo is absent, e.g. in CI."""
        baseline_xml = extractor.default_baseline()
        if not baseline_xml.is_file():
            self.skipTest(f"baseline export not found: {baseline_xml}")
        live = compare_baseline.load_baseline(str(baseline_xml))
        self.assertEqual(
            load_fixture(),
            {key: sorted(variants) for key, variants in live.items()},
            "test/fixtures/baseline-conditions.json is stale - re-run "
            "tools/extract_baseline_conditions.py and commit the fixture",
        )


if __name__ == "__main__":
    unittest.main()
