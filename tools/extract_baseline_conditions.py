#!/usr/bin/env python3
"""Extract the baseline condition variants into a committed test fixture.

Reads the Aria Operations baseline export (from the sibling repository
`vcf-security-compliance-benchmark`) and writes
`test/fixtures/baseline-conditions.json`:

    { "<condition_key>": [["<operator>", "<value>", "<valueType>", "<type>"], ...] }

Every condition key maps to the list of condition variants the baseline
defines for it (often several per-standard symptoms share a key). The fixture
is committed so the regression test (and CI) does not depend on the sibling
checkout. Re-run this script whenever the baseline export changes:

    python3 tools/extract_baseline_conditions.py \
        [--baseline ../vcf-security-compliance-benchmark/baseline/Alert-and-SymtomDefinitions.xml] \
        [--out test/fixtures/baseline-conditions.json]
"""

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SIBLING_RELATIVE = Path(
    "vcf-security-compliance-benchmark/baseline/Alert-and-SymtomDefinitions.xml"
)


def default_baseline():
    """Baseline export in the sibling checkout of the main working tree.

    Resolved via `git rev-parse --git-common-dir` so it also works from git
    worktrees (whose parent directory is not the repo's real sibling).
    """
    candidates = [REPO_ROOT.parent / SIBLING_RELATIVE]
    try:
        common_dir = Path(
            subprocess.run(
                ["git", "rev-parse", "--git-common-dir"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        ).resolve()
        candidates.append(common_dir.resolve().parent.parent / SIBLING_RELATIVE)
    except (OSError, subprocess.CalledProcessError):
        pass
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]

DEFAULT_OUT = REPO_ROOT / "test" / "fixtures" / "baseline-conditions.json"


def extract_baseline_conditions(baseline_path):
    """Map condition key -> sorted list of (operator, value, valueType, type)."""
    variants = defaultdict(set)
    tree = ET.parse(baseline_path)
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
    return {key: sorted(variant_sets) for key, variant_sets in variants.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default=str(default_baseline()),
        help="Path to Alert-and-SymtomDefinitions.xml",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help="Output fixture JSON (test/fixtures/baseline-conditions.json)",
    )
    args = parser.parse_args()

    conditions = extract_baseline_conditions(args.baseline)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(conditions, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    print(
        f"Wrote {len(conditions)} condition keys with "
        f"{sum(len(v) for v in conditions.values())} variants to {out}"
    )


if __name__ == "__main__":
    main()
