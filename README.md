# Hermes Labs CVSS Consistency

An offline, read-only CLI that checks whether CVSS 3.0 and 3.1 base scores stored in local CVE 5.x JSON records agree with their vectors. It never fetches data or tests a target.

## Replay the correction

```console
git clone https://github.com/hermes-labs-ai/hermes-labs-cvss-consistency.git
cd hermes-labs-cvss-consistency
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[test]'
python -m hermes_labs_cvss_consistency fixtures/CVE-2026-14216.before.json fixtures/CVE-2026-14216.after.json
```

The before fixture exits `1` with the CISA ADP score mismatch (`5.3` stated, `6.5` computed). The after fixture exits `0` and computes `6.5`. When both are supplied together, the mismatch makes the combined command exit `1`.

Use the checker on one CVE JSON object, a JSON array of records, or several local files:

```console
python -m hermes_labs_cvss_consistency record.json --format json
hermes-labs-cvss-consistency records-a.json records-b.json --format text
```

JSON output has a stable top-level envelope with the tool and schema versions, resolved `cvss` dependency version, file errors, and metric results. Each result contains `cve_id`, `record_index`, `metric_version`, `vector`, `stated_score`, `computed_score`, `status`, `json_path`, and `metric_source`. The record index, JSON Pointer path, and provider metadata make repeated array records and CNA versus ADP metrics distinguishable. Results are ordered by input, path, and metric version; object keys are sorted when serialized.

Statuses are `consistent`, `mismatch`, and `invalid`. Exit `0` means every metric is valid and consistent, `1` means at least one valid metric mismatches, and `2` means an input is malformed, contains no supported metric, or contains an invalid metric. The calculation dependency is pinned to `cvss==3.6`.

The fixtures preserve the complete public records at their source commits. [`fixtures/provenance.json`](fixtures/provenance.json) records repositories, paths, commits, retrieval date, source hashes, shipped hashes, and the sole byte-level transformation. The historical scanner is archived separately with its exact hash and scope in [`archive/README.md`](archive/README.md).

This fixture replay checks the CVSS score/vector inconsistency corrected in [CISA Vulnrichment issue #333](https://github.com/cisagov/vulnrichment/issues/333). It does not reproduce the original time-bounded corpus audit, vulnerability behavior, or exploitation.

CISA confirmed the correction in the issue, and the refreshed record appears in [Vulnrichment commit `4dad138`](https://github.com/cisagov/vulnrichment/commit/4dad1386622ef620991b1f7e886a92a9fd9c7d73). The exact corrected fixture comes from upstream [cvelistV5 commit `fa52a90`](https://github.com/CVEProject/cvelistV5/commit/fa52a90c974f64966065f0beb9f4ffcefaf1208f); the later Vulnrichment update bundled 114 files and should not be read as a standalone numeric correction diff.

The original fixed-snapshot run recorded 178,776 JSON records seen, 5,324 eligible CISA ADP records, and 1,060 CVSS 3.x metrics checked. Those historical counts are tied to result SHA-256 `463f28d4ba2e3bdb2eadc81758d0cb80481ab40565b616653a2fe22d1c51d6ce`; they are not output from this fixture replay.

## License and citation

The checker software is MIT licensed. The copied public records retain their upstream terms: CISA publishes Vulnrichment under [CC0-1.0](https://github.com/cisagov/vulnrichment/blob/develop/LICENSE), and cvelistV5 directs record users to the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse). Citation metadata for this software is available in [`CITATION.cff`](CITATION.cff). The companion case study is at <https://hermes-labs.ai/case-studies/cisa-vulnrichment-score-consistency>.
