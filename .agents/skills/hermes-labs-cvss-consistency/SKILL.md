---
name: hermes-labs-cvss-consistency
description: Use when local CVE 5.x JSON records need a check for whether their stated CVSS 3.0/3.1 base score agrees with the computed score from the vector string — an offline, read-only, deterministic checker that never fetches data or tests a target. No MCP.
license: MIT
compatibility: Requires Python 3.x; installs via `pip install -e '.[test]'` from a source checkout. Pins the `cvss` calculation dependency to version 3.6.
---

# Hermes Labs CVSS Consistency

An offline, read-only CLI that checks whether CVSS 3.0 and 3.1 base scores
stored in local CVE 5.x JSON records agree with their vectors. It never
fetches data or tests a target: the same input JSON always produces the same
score/vector consistency verdict, with no model calls, network access, or
randomness.

## Use it for

- Checking one CVE JSON record, a JSON array of records, or several local
  files for a stated-vs-computed CVSS score mismatch
- Getting a stable, versioned JSON envelope (tool/schema versions, per-record
  `cve_id`, `metric_version`, `vector`, `stated_score`, `computed_score`,
  `status`) for downstream tooling
- Distinguishing CNA versus ADP metric provenance on the same record via
  `metric_source` and JSON Pointer `json_path`

## Do not use it for

- Fetching CVE data from a network source — it only reads local files you
  give it
- Testing or exploiting a live target — it is a static consistency check on
  stored score/vector pairs, nothing else
- Anything beyond CVSS 3.0/3.1 base metrics — other metric versions are
  outside its scope

## Quickstart

```bash
git clone https://github.com/hermes-labs-ai/hermes-labs-cvss-consistency.git
cd hermes-labs-cvss-consistency
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[test]'
python -m hermes_labs_cvss_consistency record.json --format json
```

Check several files at once:

```bash
hermes-labs-cvss-consistency records-a.json records-b.json --format text
```

## Output shape

- JSON envelope with tool/schema versions, resolved `cvss` dependency
  version, file errors, and an array of metric results
- Each result: `cve_id`, `record_index`, `metric_version`, `vector`,
  `stated_score`, `computed_score`, `status`, `json_path`, `metric_source`
- Status is one of `consistent`, `mismatch`, or `invalid`
- Exit codes: `0` every metric valid and consistent, `1` at least one valid
  metric mismatches, `2` malformed input, no supported metric, or an invalid
  metric

## Common gotchas

- It is read-only and offline by design — do not expect it to pull fresh CVE
  data or validate against a live registry.
- Results are ordered by input, path, and metric version, and object keys
  are sorted on serialization, so diffs between runs are stable.
- The `cvss` calculation dependency is pinned to `3.6`; a different installed
  version is not the tested configuration.

## More

Full docs and fixture provenance:
https://github.com/hermes-labs-ai/hermes-labs-cvss-consistency
