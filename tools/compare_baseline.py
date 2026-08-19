#!/usr/bin/env python3
"""Compare the generated rule defaults against the Aria Operations baseline export.

Ground truth is `Alert-and-SymtomDefinitions.xml` from the sibling repository
`vcf-security-compliance-benchmark` (an actual Aria Operations export). For every
condition key present in BOTH the generated rules and the baseline, the operator,
value, value type and condition type are compared.

A rule counts as aligned when its (operator, value, valueType, type) tuple equals
ANY of the baseline variants for that key - the baseline often defines several
per-standard symptoms for the same key. Known, intentional deviations of the
single-condition model are listed in KNOWN_DEVIATIONS and reported separately.

Exit code 0 when every mismatch is a documented deviation, 1 otherwise (usable
as a CI regression test for issues #1/#2/#3/#6).

Usage:
    python3 tools/compare_baseline.py \
        [--rules rules.js] \
        [--baseline ../vcf-security-compliance-benchmark/baseline/Alert-and-SymtomDefinitions.xml]
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

DEFAULT_BASELINE = (
    "../vcf-security-compliance-benchmark/baseline/Alert-and-SymtomDefinitions.xml"
)

# condition_key -> why the generated single condition intentionally differs from
# the (multi-variant or contradictory) baseline export.
KNOWN_DEVIATIONS = {
    "config|security|disable_unexposed_features_unity_unityactive": (
        "baseline export is contradictory ('= false', '!= none', '!= true'); "
        "conservative single condition fires only when Unity IS active"
    ),
    "config|security|service:NTP Daemon|isRunning": (
        "baseline uses two collector variants ('= false', '= none'); "
        "single condition '!= true' covers both"
    ),
    "config|security|syslog_host": (
        "baseline uses two collector variants ('= false', '= none'); "
        "regex '^(false|none)$' covers both"
    ),
    "config|security|shell_timeout": (
        "baseline uses ('= 0.0', '> 900.0'); per the matrix note ('allowed "
        "range 1-900 s') and the description ('more than 15 minutes') the "
        "violation is '> 900.0'; the disabled state '= 0.0' is an accepted "
        "blind spot of the single-condition model"
    ),
    "config|security|shell_interactive_timeout": (
        "baseline uses ('= 0.0', '> 900.0'); per the matrix note ('allowed "
        "range 1-900 s') the violation is '> 900.0'; the disabled state "
        "'= 0.0' is an accepted blind spot of the single-condition model"
    ),
    "config|security|security_account_lock_failures": (
        "baseline encodes the SCG variants as '< 3.0' and '> 3.0' (union == "
        "'!= 3.0') plus the ISO variant '!= 5.0'; strictest value is 3, so the "
        "ISO variant is intentionally dropped"
    ),
    "summary|ComplianceMetrics|backup_enabled": (
        "baseline defines the symptom twice with opposite directions ('= false' "
        "and '= true'); the single condition '!= true' fires when backup is not "
        "enabled (direction per matrix note)"
    ),
}


def load_rules(path):
    """Parse the generated rules.js (a single `const RULES_DATA = {...};` statement)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"const\s+RULES_DATA\s*=\s*(\{.*\})\s*;\s*$", text, re.DOTALL)
    if not m:
        raise SystemExit(f"{path}: cannot find `const RULES_DATA = {{...}};`")
    payload = json.loads(m.group(1))
    return payload["rules"]


def load_baseline(path):
    """Map condition key -> set of (operator, value, valueType, type) variants."""
    variants = defaultdict(set)
    tree = ET.parse(path)
    for symptom in tree.getroot().findall(".//SymptomDefinition"):
        for cond in symptom.findall("./State/Condition"):
            variants[cond.get("key")].add(
                (
                    cond.get("operator"),
                    cond.get("value"),
                    cond.get("valueType"),
                    cond.get("type"),
                )
            )
    return variants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", default="rules.js", help="Generated rules.js")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="Baseline XML")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    baseline = load_baseline(args.baseline)

    aligned, deviations, unexplained = [], [], []
    rule_keys = {r["conditionKey"] for r in rules}
    for rule in rules:
        key = rule["conditionKey"]
        if key not in baseline:
            continue
        actual = (rule["operator"], rule["value"], rule["valueType"], rule["type"])
        if actual in baseline[key]:
            aligned.append((key, actual))
        elif key in KNOWN_DEVIATIONS:
            deviations.append((key, actual, sorted(baseline[key]), KNOWN_DEVIATIONS[key]))
        else:
            unexplained.append((key, actual, sorted(baseline[key])))

    baseline_only = sorted(set(baseline) - rule_keys)
    rules_only = sorted(rule_keys - set(baseline))

    def fmt_cond(cond):
        op, value, vtype, ctype = cond
        return f"{op} {value!r} [{vtype}/{ctype}]"

    print(f"rules: {len(rules)}  baseline condition keys: {len(baseline)}")
    print(f"shared keys: {len(aligned) + len(deviations) + len(unexplained)}\n")

    print(f"ALIGNED ({len(aligned)}):")
    for key, cond in sorted(aligned):
        print(f"  ok   {key}: {fmt_cond(cond)}")

    print(f"\nDOCUMENTED DEVIATIONS ({len(deviations)}):")
    for key, actual, expected, reason in sorted(deviations):
        print(f"  dev  {key}:")
        print(f"       generated : {fmt_cond(actual)}")
        for cond in expected:
            print(f"       baseline  : {fmt_cond(cond)}")
        print(f"       reason    : {reason}")

    print(f"\nUNEXPLAINED MISMATCHES ({len(unexplained)}):")
    for key, actual, expected in sorted(unexplained):
        print(f"  BAD  {key}:")
        print(f"       generated : {fmt_cond(actual)}")
        for cond in expected:
            print(f"       baseline  : {fmt_cond(cond)}")

    print(f"\nbaseline-only keys (out of scope): {len(baseline_only)}")
    for key in baseline_only:
        print(f"  -    {key}")
    print(f"rules-only keys (no baseline counterpart): {len(rules_only)}")
    for key in rules_only:
        print(f"  +    {key}")

    shared = len(aligned) + len(deviations) + len(unexplained)
    print(f"\nsummary: {len(aligned)}/{shared} aligned, "
          f"{len(deviations)} documented deviations, {len(unexplained)} unexplained")
    if unexplained:
        print("FAIL: unexplained mismatches against the baseline", file=sys.stderr)
        return 1
    print("PASS: every mismatch is a documented deviation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
