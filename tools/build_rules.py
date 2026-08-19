#!/usr/bin/env python3
"""Build rules.js for the VCF Operations Scorecard Builder.

Reads the scrubbed decision matrix CSV (`data/decision-matrix.csv` in this repo)
and emits a JavaScript data file consumed by index.html.

Defaults are derived from the `strictest_requirement` column of the source matrix.
That column describes the DESIRED (compliant) state, while a symptom condition
must fire on the VIOLATION. Comparison operators are therefore inverted during
derivation: `=` -> `!=`, `≠` -> `=`, `≥` -> `<`, `≤` -> `>`, `>` -> `<=`, `<` -> `>=`.
`contains` and `regex` requirements are already violation-style matchers and are
kept verbatim.

Usage:
    python3 tools/build_rules.py [--csv data/decision-matrix.csv] [--out rules.js]
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter

# vCenter / Aria Operations adapter kind per resource kind.
ADAPTER_KIND = {
    "VirtualMachine": "VMWARE",
    "HostSystem": "VMWARE",
    "DistributedVirtualPortgroup": "VMWARE",
    "VmwareDistributedVirtualSwitch": "VMWARE",
    "ManagementService": "NSXTAdapter",
    "NSXTAdapterInstance": "NSXTAdapter",
    "CacheDisk": "VirtualAndPhysicalSANAdapter",
    "CapacityDisk": "VirtualAndPhysicalSANAdapter",
    "VirtualSANDCCluster": "VirtualAndPhysicalSANAdapter",
}

# Remediation recommendation reference per adapter kind.
RECOMMENDATION = {
    "VMWARE": "Recommendation-df-VMWARE-FixHardeningViolations",
    "NSXTAdapter": "Recommendation-df-NSX-Security-Guidelines",
    "VirtualAndPhysicalSANAdapter": "Recommendation-df-VirtualAndPhysicalSANAdapter-FixHardeningViolations",
}

# Requirement spelling in the matrix -> canonical operator (desired state).
OPERATOR_MAP = {
    "=": "=",
    "!=": "!=",
    "\u2260": "!=",  # !=
    "<": "<",
    "<=": "<=",
    "\u2264": "<=",  # <=
    ">": ">",
    ">=": ">=",
    "\u2265": ">=",  # >=
}

# Desired-state operator -> violation operator used by the symptom condition.
INVERTED_OPERATOR = {
    "=": "!=",
    "!=": "=",
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
}

COMPARISON_OPERATORS = {"=", "!=", "<", "<=", ">", ">="}

# `!=` must be matched before the single-char class so ASCII "not equal"
# cells parse like their `\u2260` spelling instead of falling through to the
# bare-value branch (which would keep the operator text inside the value).
OP_PATTERN = re.compile(r"^(<=|>=|!=|[=\u2260<\u2264>\u2265])\s*(.+)$", re.DOTALL)
NUMERIC_PATTERN = re.compile(r"^-?\d+(\.\d+)?$")

# Timeout rows carry a bare reference value in `strictest_requirement`. Per the
# matrix notes the symptom reports "< reference": a timeout below the reference
# (including 0 = disabled) is the violation.
TIMEOUT_CONDITION_KEYS = frozenset(
    {
        "config|security|dcui_timeout",
        "config|security|host_client_session_timeout",
        "config|security|shell_timeout",
        "config|security|shell_interactive_timeout",
    }
)

# The baseline export uses metric conditions for exactly these two keys; every
# other key (including all ComplianceMetrics|* keys) is a property condition.
METRIC_CONDITION_KEYS = frozenset(
    {
        "security|NtpServersCount",
        "security|SshEnabled",
    }
)

# English shorthand cells in `strictest_requirement`. The cells describe the
# desired state; the tuples carry the derived VIOLATION semantics plus a note
# documenting why the single condition deviates from the multi-variant baseline.
VALUE_ALIASES = {
    "running": (
        "!=",
        "true",
        "desired state: NTP daemon running; the single condition '!= true' "
        "covers both baseline collector variants ('= false' and '= none')",
    ),
    "configured": (
        "regex",
        "^(false|none)$",
        "desired state: remote syslog configured; the regex covers both "
        "baseline collector variants ('= false' and '= none')",
    ),
    "false / not set": (
        "=",
        "true",
        "desired state: Unity not active; conservative single condition for "
        "the contradictory baseline export ('= false', '!= none', '!= true') "
        "- fires only when Unity IS active",
    ),
}

# German leftovers must not creep back into the English-only matrix (issue #7).
GERMAN_TOKENS = ("nicht", "gesetzt", "l\u00e4uft", "konfiguriert", "kein alert", "skript")
GERMAN_CHARS = set("\u00e4\u00f6\u00fc\u00df\u00c4\u00d6\u00dc")


def assert_no_german(csv_path):
    """Abort the build if the matrix contains German tokens or umlauts (issue #7)."""
    problems = []
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, start=1):
            lowered = line.lower()
            problems.extend(
                f"line {lineno}: German token {token!r}"
                for token in GERMAN_TOKENS
                if token in lowered
            )
            problems.extend(
                f"line {lineno}: German umlaut {ch!r}"
                for ch in line
                if ch in GERMAN_CHARS
            )
    if problems:
        raise SystemExit(
            f"{csv_path} still contains German; translate the cells and re-run:\n  "
            + "\n  ".join(problems)
        )


def vmx_violation_regex(min_version):
    """Regex matching hardware versions BELOW vmx-<min_version> (the violation).

    Mirrors the baseline export: the requirement `vmx-19+` becomes
    `vmx-[1-9]|vmx-1[0-8]`, which matches vmx-4 through vmx-18 (issue #1).
    """
    n = int(min_version)
    if not 11 <= n <= 20:
        raise ValueError(
            f"cannot derive a below-vmx-{n} regex for the 'vmx-{n}+' requirement; "
            "extend tools/build_rules.py"
        )
    return f"vmx-[1-9]|vmx-1[0-{n - 11}]"


def normalize_number(value):
    """Render whole numbers with a trailing `.0`, like Aria Operations exports."""
    return value if "." in value else value + ".0"


def parse_requirement(raw, condition_key=""):
    """Parse a strictest_requirement cell into (operator, value, derivation_note).

    The cell describes the desired state; the returned operator/value describe
    the violation that makes the symptom fire (issue #2).
    """
    text = raw.strip()

    # "contains X" is already a violation-style matcher - keep it verbatim
    # (verified against the baseline for firewallRule:services|servicesConfigured).
    m = re.match(r"^contains\s+(.+)$", text, re.IGNORECASE)
    if m:
        return "contains", m.group(1).strip(), None

    # English shorthand cells with hand-derived violation semantics (issue #6).
    if text in VALUE_ALIASES:
        op, value, note = VALUE_ALIASES[text]
        return op, value, note

    # "vmx-19+" means "at least vmx-19"; the violation is any lower hardware
    # version, matched with a regex like the baseline export (issue #1).
    m = re.match(r"^vmx-(\d+)\+$", text)
    if m:
        return (
            "regex",
            vmx_violation_regex(m.group(1)),
            f"required: hardware version >= vmx-{m.group(1)}; "
            "regex matches the violating (lower) hardware versions",
        )

    m = OP_PATTERN.match(text)
    if m:
        op, value = OPERATOR_MAP[m.group(1)], m.group(2).strip()
    else:
        # A bare value ("600", "3", "off", ...) means "= value" is required.
        op, value = "=", text

    if op in COMPARISON_OPERATORS and NUMERIC_PATTERN.match(value):
        value = normalize_number(value)

    # Desired state -> violation.
    op = INVERTED_OPERATOR[op]

    # Timeout rows: a bare reference value means "at least <reference> seconds";
    # 0 (disabled) must fire as well, so the violation is "< reference"
    # (see the matrix notes; matches the baseline export).
    if condition_key in TIMEOUT_CONDITION_KEYS and op == "!=":
        op = "<"
        note = (
            "timeout reference value; the violation is '<' reference "
            "(0 = disabled also fires)"
        )
    else:
        note = None

    return op, value, note


def condition_type(key):
    """Default condition type: `metric` only for the two keys the baseline export
    uses as metrics, `property` for everything else (issue #3)."""
    return "metric" if key in METRIC_CONDITION_KEYS else "property"


def value_type(operator, value):
    """`numeric` only for plain comparisons on numeric values; `contains` and
    `regex` always compare strings."""
    if operator in COMPARISON_OPERATORS and NUMERIC_PATTERN.match(value):
        return "numeric"
    return "string"


def slugify(text, max_len=90):
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")
    return slug[:max_len].strip("-")


def stable_suffix(condition_key, scg_id):
    """Order-independent disambiguation suffix for colliding slugs (issue #11):
    first 8 hex chars of sha256(condition_key + '|' + scg_id)."""
    digest = hashlib.sha256(f"{condition_key}|{scg_id}".encode("utf-8")).hexdigest()
    return digest[:8]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        default="data/decision-matrix.csv",
        help="Path to decision-matrix.csv",
    )
    parser.add_argument("--out", default="rules.js", help="Output file")
    args = parser.parse_args()

    assert_no_german(args.csv)

    entries = []
    seen_keys = set()
    with open(args.csv, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            resource = row["resource"].strip()
            key = row["condition_key"].strip()
            scg_id = row["scg_id"].strip()
            if key in seen_keys:
                raise SystemExit(f"duplicate condition_key in {args.csv}: {key}")
            seen_keys.add(key)
            op, value, derivation = parse_requirement(
                row["strictest_requirement"], key
            )
            note = row.get("note", "").strip()
            if derivation:
                note = (note + " " if note else "") + f"Derivation: {derivation}."
            entries.append(
                {
                    "id": None,  # assigned below, after collision analysis
                    "resource": resource,
                    "adapterKind": ADAPTER_KIND.get(resource, "VMWARE"),
                    "recommendation": RECOMMENDATION.get(
                        ADAPTER_KIND.get(resource, "VMWARE"),
                        "Recommendation-df-VMWARE-FixHardeningViolations",
                    ),
                    "scgId": "" if scg_id == "\u2013" else scg_id,
                    "description": row["description"].strip(),
                    "conditionKey": key,
                    "type": condition_type(key),
                    "operator": op,
                    "value": value,
                    "valueType": value_type(op, value),
                    "note": note,
                    "_slug_base": scg_id if scg_id and scg_id != "\u2013" else key,
                    "_scg_id_raw": scg_id,
                }
            )

    # Assign symptom IDs. When several rows produce the same slug, every
    # colliding row gets a stable hash suffix instead of the CSV row index, so
    # reordering the matrix no longer changes symptom IDs (issue #11).
    slug_counts = Counter(slugify(e["_slug_base"]) or "rule" for e in entries)
    for e in entries:
        slug = slugify(e["_slug_base"]) or "rule"
        uid = f"SymptomDefinition-VCF-SEC-{slug}"
        if slug_counts[slug] > 1:
            uid = f"{uid}-{stable_suffix(e['conditionKey'], e['_scg_id_raw'])}"
        e["id"] = uid
        del e["_slug_base"]
        del e["_scg_id_raw"]

    payload = {
        "source": args.csv,
        "count": len(entries),
        "rules": entries,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("// Generated by tools/build_rules.py - do not edit by hand.\n")
        fh.write("const RULES_DATA = ")
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write(";\n")
    print(f"Wrote {len(entries)} rules to {args.out}")


if __name__ == "__main__":
    main()
