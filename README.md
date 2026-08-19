# VCF Operations Scorecard Builder

A single-page, client-side web app that builds custom **VMware Aria Operations** compliance
content for a VMware Cloud Foundation (VCF) security benchmark:

- **`Alert-and-SymptomDefinitions.xml`** – one symptom definition per rule, grouped into one
  alert definition per resource kind
- **`Compliance-Scorecard.xml`** – a custom compliance scorecard referencing the generated alerts

The app ships with defaults following the **strictest requirement** across two public
benchmark sources:

- [vSphere 8 Security Configuration Guide](https://www.vmware.com/resources/hardening-guides)
  (the VCF/vSphere Hardening Guide)
- the **ISO 27001 compliance check for VCF Operations**, available in the
  [VCF Solutions Catalog](https://vcf.broadcom.com/vsc/) (formerly VMware Marketplace)

Every rule can be customized in the UI before exporting:

- include / exclude individual rules
- change the condition operator (`=`, `!=`, `<`, `<=`, `>`, `>=`, `contains`, `regex`)
- change the comparison value
- switch the condition type between `property` and `metric`
- set scorecard name, symptom severity and definition ID prefix

Customizations are persisted in the browser's `localStorage` only. No data leaves the browser;
the app has no backend.

## Usage

Open `index.html` in a browser, or host the folder on any static file host.

### GitHub Pages

1. Push this repository to GitHub.
2. In the repository settings, enable **Pages** with the source set to the root of the main branch.
3. Open `https://<user>.github.io/<repo>/`.

### Importing the generated files

1. In Aria Operations, go to **Configure > Alerts > Alert Definitions** and import
   `Alert-and-SymptomDefinitions.xml` (symptom definitions and recommendations included in the
   same file are imported together).
2. Go to **Operations > Compliance > Custom Compliance** (or the scorecard management page of
   your version) and import `Compliance-Scorecard.xml`.
3. Review and test the content on a non-production instance first.

## Repository layout

| Path | Description |
| --- | --- |
| `index.html` | The complete single-page app (UI + XML generation, Clarity Design based) |
| `data/decision-matrix.csv` | Scrubbed rule source (English only; the build fails on German leftovers) |
| `rules.js` | Generated rule data (144 rules) |
| `tools/build_rules.py` | Regenerates `rules.js` from the decision matrix CSV |
| `tools/compare_baseline.py` | Regression check of the generated defaults against the baseline export |

Regenerate the rule data after the underlying rule source changes:

```bash
python3 tools/build_rules.py --csv data/decision-matrix.csv --out rules.js
```

### Default derivation

The `strictest_requirement` column describes the **desired (compliant)** state;
symptom conditions must fire on the **violation**, so comparison operators are
inverted during derivation (`=` → `!=`, `≠` → `=`, `≥` → `<`, `≤` → `>`,
`>` → `<=`, `<` → `>=`). `contains`/`regex` requirements are kept verbatim,
and whole-number values are normalized to the `.0` float spelling used by
Aria Operations exports. Rows whose requirement is a multi-variant check
(NTP daemon, syslog host, Unity) are collapsed into a single condition whose
semantics are documented in the rule note.

### Baseline comparison

The defaults are validated against the Aria Operations baseline export in the
sibling repository [`vcf-security-compliance-benchmark`](https://github.com/Benedikt-Frenzel/vcf-security-compliance-benchmark)
(`baseline/Alert-and-SymtomDefinitions.xml`). With that repository checked out
next to this one:

```bash
python3 tools/compare_baseline.py
```

The tool reports operator/value/type alignment for every shared condition key
and exits non-zero on any mismatch that is not a documented deviation, so it
can be used as a CI regression test.

## Tech notes

- UI styled with [Clarity Design](https://clarity.design/) (`@clr/ui` CSS and the Clarity City
  typeface, loaded from CDN).
- Generated symptom IDs follow the pattern `SymptomDefinition-<prefix>-<slug>` and alert IDs
  `AlertDefinition-<prefix>-<RESOURCEKIND>`; the prefix is configurable (default `VCF-SEC`).
- Adapter kinds and remediation recommendations per resource kind mirror the baseline files in
  `vcf-security-compliance-benchmark/baseline/`.

## Disclaimer

This is a **personal, community-driven project**. It is not an official product of, and is
**not supported by, Broadcom Inc. or its subsidiaries** (including VMware). Use the generated
content at your own risk and always validate it in a non-production environment before rollout.
