"""Unit tests for tools/build_rules.py (stdlib unittest only).

The module under test is imported from its file path so the tests run from any
working directory (CI checks out the repo without installing anything).
"""

import csv
import hashlib
import importlib.util
import io
import json
import random
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = REPO_ROOT / "data" / "decision-matrix.csv"
RULES_JS_PATH = REPO_ROOT / "rules.js"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_rules = load_module("build_rules", REPO_ROOT / "tools" / "build_rules.py")

VALID_OPERATORS = {"=", "!=", "<", "<=", ">", ">=", "contains", "regex"}


def run_builder(tmp_dir, csv_path, out_name="rules.js"):
    """Run build_rules.main() in-process with the given csv, return parsed payload.

    For the real matrix the csv is referenced relative to the repo root (cwd is
    switched) so the recorded `source` matches the committed rules.js byte for
    byte in the freshness test.
    """
    out_path = Path(tmp_dir) / out_name
    csv_arg = str(csv_path)
    if Path(csv_path).resolve() == CSV_PATH.resolve():
        csv_arg = "data/decision-matrix.csv"
    argv, cwd = sys.argv, Path.cwd()
    sys.argv = ["build_rules.py", "--csv", csv_arg, "--out", str(out_path)]
    try:
        import os

        os.chdir(REPO_ROOT)
        with redirect_stdout(io.StringIO()):
            build_rules.main()
    finally:
        sys.argv = argv
        import os

        os.chdir(cwd)
    text = out_path.read_text(encoding="utf-8")
    return json.loads(re.search(r"const RULES_DATA = (\{.*\});", text, re.DOTALL).group(1))


def write_csv(path, rows):
    """Write a minimal decision matrix with the real header and the given rows."""
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
        header = next(csv.reader(fh))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


class ParseRequirementTests(unittest.TestCase):
    """parse_requirement turns desired-state cells into violation conditions."""

    def test_operator_inversion(self):
        # The matrix states the DESIRED state; symptoms fire on violations,
        # so comparison operators are inverted (the P0 fixed in PR #16).
        cases = [
            ("= 5", "!=", "5.0"),
            ("= 40.0", "!=", "40.0"),
            ("\u2260 true", "=", "true"),      # != true  -> = true
            ("\u2260 syslog", "=", "syslog"),
            ("\u2265 3.0", "<", "3.0"),
            ("\u2264 900", ">", "900.0"),
            ("> 5", "<=", "5.0"),
            ("< 2", ">=", "2.0"),
            (">= 7", "<", "7.0"),
            ("<= 8", ">", "8.0"),
            ("!= 3", "=", "3.0"),
        ]
        for raw, operator, value in cases:
            with self.subTest(raw=raw):
                op, val, _ = build_rules.parse_requirement(raw)
                self.assertEqual((op, val), (operator, value))

    def test_unicode_and_ascii_operators_map_identically(self):
        for desired, operator in [
            ("=", "="),
            ("\u2260", "!="),
            ("\u2264", "<="),
            ("\u2265", ">="),
        ]:
            with self.subTest(operator=operator):
                op, _, _ = build_rules.parse_requirement(desired + " 1")
                self.assertEqual(op, build_rules.INVERTED_OPERATOR[operator])

    def test_bare_value_means_equals_then_inverted(self):
        op, value, _ = build_rules.parse_requirement("600")
        self.assertEqual((op, value), ("!=", "600.0"))

    def test_whole_numbers_get_trailing_zero(self):
        # Aria Operations exports render numbers as e.g. "40.0".
        _, value, _ = build_rules.parse_requirement("= 40")
        self.assertEqual(value, "40.0")
        _, value, _ = build_rules.parse_requirement("= 40.5")
        self.assertEqual(value, "40.5")
        _, value, _ = build_rules.parse_requirement("= off")
        self.assertEqual(value, "off")

    def test_contains_is_not_inverted(self):
        # "contains X" is already a violation-style matcher - kept verbatim.
        op, value, _ = build_rules.parse_requirement("contains false")
        self.assertEqual((op, value), ("contains", "false"))
        self.assertNotIn(op, build_rules.INVERTED_OPERATOR)

    def test_vmx_requirement_becomes_below_regex(self):
        op, value, note = build_rules.parse_requirement("vmx-19+")
        self.assertEqual(op, "regex")
        self.assertEqual(value, "vmx-[1-9]|vmx-1[0-8]")
        self.assertIn("vmx-19", note)

        op, value, _ = build_rules.parse_requirement("vmx-13+")
        self.assertEqual((op, value), ("regex", "vmx-[1-9]|vmx-1[0-2]"))

    def test_vmx_regex_matches_exactly_the_lower_versions(self):
        for req, highest in [("vmx-13+", 12), ("vmx-19+", 18)]:
            _, pattern, _ = build_rules.parse_requirement(req)
            rx = re.compile(pattern)
            with self.subTest(pattern=pattern):
                for version in range(1, highest + 1):
                    self.assertIsNotNone(rx.fullmatch(f"vmx-{version}"), f"vmx-{version} should match")
                for version in (0, highest + 1, 20, 21):
                    self.assertIsNone(rx.fullmatch(f"vmx-{version}"), f"vmx-{version} must not match")

    def test_vmx_out_of_supported_range_raises(self):
        for bad in ("vmx-10+", "vmx-21+"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_rules.parse_requirement(bad)

    def test_english_value_aliases(self):
        # English shorthand cells with hand-derived VIOLATION semantics (issue #6).
        cases = {
            "running": ("!=", "true"),
            "configured": ("regex", "^(false|none)$"),
            "false / not set": ("=", "true"),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                op, value, note = build_rules.parse_requirement(raw)
                self.assertEqual((op, value), expected)
                self.assertTrue(note, "alias deviations must carry an explanation")

    def test_dcui_style_timeout_rows_report_below_reference(self):
        # dcui/host_client carry the matrix note "symptom reports < reference"
        for key in sorted(build_rules.TIMEOUT_LT_REFERENCE_KEYS):
            with self.subTest(key=key):
                op, value, _ = build_rules.parse_requirement("600", key)
                self.assertEqual((op, value), ("<", "600.0"))
                op, value, _ = build_rules.parse_requirement("= 900", key)
                self.assertEqual((op, value), ("<", "900.0"))

    def test_shell_timeout_rows_report_above_reference(self):
        # shell timeouts: "allowed range 1-900 s" -> the violation is > reference
        for key in sorted(build_rules.TIMEOUT_GT_REFERENCE_KEYS):
            with self.subTest(key=key):
                op, value, _ = build_rules.parse_requirement("900", key)
                self.assertEqual((op, value), (">", "900.0"))
                op, value, _ = build_rules.parse_requirement("= 900", key)
                self.assertEqual((op, value), (">", "900.0"))

    def test_non_timeout_rows_do_not_get_timeout_semantics(self):
        op, value, _ = build_rules.parse_requirement("600", "config|security|other")
        self.assertEqual((op, value), ("!=", "600.0"))


class ConditionTypeTests(unittest.TestCase):
    def test_metric_only_for_the_two_baseline_metric_keys(self):
        self.assertEqual(build_rules.condition_type("security|NtpServersCount"), "metric")
        self.assertEqual(build_rules.condition_type("security|SshEnabled"), "metric")

    def test_everything_else_is_property(self):
        for key in (
            "config|version",
            "config|security|dcui_timeout",
            "ComplianceMetrics|APILimits|Client_API_Concurrency_Limit",
            "summary|ComplianceMetrics|backup_enabled",
            "security|SomethingElse",
        ):
            with self.subTest(key=key):
                self.assertEqual(build_rules.condition_type(key), "property")


class ValueTypeTests(unittest.TestCase):
    def test_numeric_only_for_comparisons_on_numeric_values(self):
        for operator in ("=", "!=", "<", "<=", ">", ">="):
            with self.subTest(operator=operator):
                self.assertEqual(build_rules.value_type(operator, "40.0"), "numeric")
                self.assertEqual(build_rules.value_type(operator, "-3"), "numeric")
                self.assertEqual(build_rules.value_type(operator, "true"), "string")
                self.assertEqual(build_rules.value_type(operator, "Enabled"), "string")

    def test_contains_and_regex_are_always_string(self):
        self.assertEqual(build_rules.value_type("contains", "false"), "string")
        self.assertEqual(build_rules.value_type("contains", "42"), "string")
        self.assertEqual(build_rules.value_type("regex", "^(false|none)$"), "string")
        self.assertEqual(build_rules.value_type("regex", "vmx-[1-9]"), "string")


class GermanGuardTests(unittest.TestCase):
    """The matrix must stay English-only (issue #7)."""

    def test_clean_csv_passes(self):
        build_rules.assert_no_german(CSV_PATH)  # must not raise

    def test_german_tokens_are_rejected(self):
        for token in ("nicht", "gesetzt", "l\u00e4uft", "konfiguriert", "kein alert", "skript"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "matrix.csv"
                path.write_text(f"resource,strictest_requirement\nHostSystem,= {token}\n", encoding="utf-8")
                with self.assertRaises(SystemExit):
                    build_rules.assert_no_german(path)

    def test_umlauts_are_rejected(self):
        for ch in "\u00e4\u00f6\u00fc\u00df\u00c4\u00d6\u00dc":
            with self.subTest(ch=ch), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "matrix.csv"
                path.write_text(f"resource,strictest_requirement\nHostSystem,= w{ch}rd\n", encoding="utf-8")
                with self.assertRaises(SystemExit):
                    build_rules.assert_no_german(path)

    def test_builder_aborts_on_german_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.csv"
            write_csv(path, [["HostSystem", "\u2013", "d", "k|l\u00e4uft", "", "", "", "", "", "", "", "= true", ""]])
            with self.assertRaises(SystemExit):
                run_builder(tmp, path)


class StableIdTests(unittest.TestCase):
    def test_stable_suffix_is_truncated_sha256(self):
        suffix = build_rules.stable_suffix("config|a", "SCG-ID")
        digest = hashlib.sha256("config|a|SCG-ID".encode("utf-8")).hexdigest()
        self.assertEqual(suffix, digest[:8])
        self.assertEqual(suffix, build_rules.stable_suffix("config|a", "SCG-ID"))

    def test_colliding_slugs_get_distinct_hash_suffixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.csv"
            write_csv(
                path,
                [
                    ["VirtualMachine", "Same Slug", "one", "key|one", "", "", "", "", "", "", "", "= true", ""],
                    ["VirtualMachine", "Same Slug", "two", "key|two", "", "", "", "", "", "", "", "= false", ""],
                ],
            )
            payload = run_builder(tmp, path)
            ids = [r["id"] for r in payload["rules"]]
            self.assertEqual(ids[0], "SymptomDefinition-VCF-SEC-Same-Slug-" + build_rules.stable_suffix("key|one", "Same Slug"))
            self.assertEqual(ids[1], "SymptomDefinition-VCF-SEC-Same-Slug-" + build_rules.stable_suffix("key|two", "Same Slug"))
            self.assertNotEqual(ids[0], ids[1])

    def test_row_order_does_not_change_ids(self):
        """Shuffling the matrix must not reshuffle symptom IDs (issue #11)."""
        with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.reader(fh))
        header, data = rows[0], rows[1:]
        self.assertGreater(len(data), 1)
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            shuffled = data[:]
            random.Random(20260819).shuffle(shuffled)
            for name, rows_ in (("a", data), ("b", shuffled)):
                path = Path(tmp1) / f"{name}.csv"
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(header)
                    writer.writerows(rows_)
            first = run_builder(tmp1, Path(tmp1) / "a.csv")
            second = run_builder(tmp2, Path(tmp1) / "b.csv")
            self.assertEqual(first["count"], second["count"])
            self.assertEqual(
                sorted(r["id"] for r in first["rules"]),
                sorted(r["id"] for r in second["rules"]),
            )

    def test_real_matrix_collision_uses_hash_suffix(self):
        # The real matrix contains at least one slug collision ("Integrity"):
        # those IDs must end in the stable hash suffix, never in a row index.
        with tempfile.TemporaryDirectory() as tmp:
            payload = run_builder(tmp, CSV_PATH)
            suffixed = [r["id"] for r in payload["rules"] if re.search(r"-[0-9a-f]{8}$", r["id"])]
            self.assertGreaterEqual(len(suffixed), 2, "expected the known Integrity collision in the matrix")
            with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
                raw = {row["condition_key"]: row["scg_id"] for row in csv.DictReader(fh)}
            for rule in payload["rules"]:
                if rule["id"] not in suffixed:
                    continue
                scg_raw = raw[rule["conditionKey"]]
                expected = (
                    "SymptomDefinition-VCF-SEC-"
                    + build_rules.slugify(scg_raw)
                    + "-"
                    + build_rules.stable_suffix(rule["conditionKey"], scg_raw)
                )
                self.assertEqual(rule["id"], expected)


class EndToEndTests(unittest.TestCase):
    """Run the builder against the real decision matrix."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.payload = run_builder(cls.tmp.name, CSV_PATH)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_count_is_144(self):
        self.assertEqual(self.payload["count"], 144)
        self.assertEqual(len(self.payload["rules"]), 144)

    def test_ids_are_unique(self):
        ids = [r["id"] for r in self.payload["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        for uid in ids:
            self.assertRegex(uid, r"^SymptomDefinition-VCF-SEC-[A-Za-z0-9-]+$")

    def test_condition_keys_are_unique(self):
        keys = [r["conditionKey"] for r in self.payload["rules"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_all_operators_valid(self):
        for rule in self.payload["rules"]:
            self.assertIn(rule["operator"], VALID_OPERATORS, rule["conditionKey"])

    def test_value_types_consistent_with_operators(self):
        for rule in self.payload["rules"]:
            with self.subTest(key=rule["conditionKey"]):
                self.assertEqual(
                    rule["valueType"],
                    build_rules.value_type(rule["operator"], rule["value"]),
                )

    def test_issue1_evidence_rows(self):
        """The P0 examples from issue #1: desired-state cells correctly inverted."""
        by_key = {r["conditionKey"]: r for r in self.payload["rules"]}
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

    def test_committed_rules_js_is_in_sync(self):
        """The committed rules.js must be exactly what the builder regenerates.

        This is the freshness gate: edit data/decision-matrix.csv (or the
        builder) and re-run `python3 tools/build_rules.py` before committing.
        """
        generated = Path(self.tmp.name) / "rules.js"
        self.assertEqual(generated.read_text(encoding="utf-8"), RULES_JS_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
