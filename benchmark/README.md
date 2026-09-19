# CVSS consistency challenge v1

Try your own checker on ten public cases and publish a reproducible result. The
job is to classify each record as `consistent`, `mismatch`, or `invalid` from its
stored CVSS 3.1 score and vector. No model, credentials, target scanning, or
network access is needed for the reference run after installation.

## Run the reference

From the repository root after `python -m pip install -e '.[test]'`:

```console
python benchmark/run.py reference > predictions.json
python benchmark/run.py score predictions.json
```

The reference should produce `correct: 10`, `total: 10`, `accuracy: 1.0`, and no
failed cases. This is a small open starter challenge, not a held-out evaluation
or an estimate of performance on the CVE corpus. Do not present it as proof that
a checker finds vulnerabilities or that one product outperforms another.

## Run your own checker

Read `cases.json`. Each case contains either an inline synthetic `record` or a
repository-relative `fixture` path. Ignore the published `expected` answer when
running your implementation. Evaluate every supported metric in each record:

- `invalid`: a supported metric is invalid, or there are no supported metrics;
- `mismatch`: all supported metrics are valid and at least one score disagrees;
- `consistent`: all supported metrics are valid and their scores agree.

Write a JSON object mapping **every case ID** to one of those three labels, then
run the same `score` command. Missing, additional, duplicate IDs and unknown
labels are rejected instead of being silently omitted. Accuracy is correct cases
divided by all ten cases; the confusion table uses expected labels as rows and
predicted labels as columns. There is no timing or throughput ranking.

## Share results or propose a harder case

[Open a benchmark-result issue](https://github.com/hermes-labs-ai/hermes-labs-cvss-consistency/issues/new?template=benchmark-result.yml).
Include the exact repository commit, implementation/version, environment,
reproduction command, predictions, and scorer output. Public submissions are
self-reported until another person reproduces them. The repository maintainers
review submissions through this issue queue; there is no response-time promise.
Do not upload private records, tokens, or customer data.

The v1 manifest is the comparison unit. Cite its Git commit with every result.
Any future case or label change requires a new benchmark version so older results
remain comparable. Propose new cases separately; do not modify the historical
fixtures.

## Provenance and limits

Two fixtures replay the public correction documented in CISA Vulnrichment issue
#333. Their source commits, hashes and upstream terms remain in
[`fixtures/provenance.json`](../fixtures/provenance.json) and the root README.
The other eight cases are synthetic records authored here, under the repository's
existing MIT license. The 6.5 and 9.8 expected values follow the
[FIRST CVSS 3.1 specification](https://www.first.org/cvss/v3.1/specification-document).
Invalid cases test input handling, not new security findings. Labels are public,
the set is small and unbalanced, and eight cases reuse two vectors. Passing does
not establish general CVSS coverage or replay the original corpus audit.
