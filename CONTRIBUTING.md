# Contributing

hermes-labs-cvss-consistency is a small, single-purpose offline checker. Contributions are welcome; this doc covers the minimum needed to set up, change, and test the code.

## Environment setup

```console
git clone https://github.com/hermes-labs-ai/hermes-labs-cvss-consistency.git
cd hermes-labs-cvss-consistency
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[test]'
```

This installs the package in editable mode plus `pytest` and `ruff`.

## Running the tests

The focused replay test is `tests/test_replay.py`; it checks that the CISA
ADP score/vector mismatch in `fixtures/CVE-2026-14216.before.json` is
detected and that `fixtures/CVE-2026-14216.after.json` is reported
consistent:

```console
python -m pytest -q tests/test_replay.py
```

To run the full test suite:

```console
python -m pytest -q
```

`ruff check .` is also run in CI and should pass before you open a pull request.

## Fixtures and provenance

The files under `fixtures/` are copies of real, public CVE records used to
replay a specific, documented correction (see the README's "Replay the
correction" section). [`fixtures/provenance.json`](fixtures/provenance.json)
records each fixture's source repository, path, commit, retrieval date, and
SHA-256 hashes before and after the sole documented transformation.

Do not edit existing fixture files. If a change requires a new or updated
fixture, add it alongside a corresponding `provenance.json` entry so the
source and hash trail stays verifiable.

Use GitHub issues and pull request reviews for proposal and review discussion. Keep
tracked changes focused on reusable code, tests, documentation, fixtures, and
provenance that support reproducible checks beyond an individual review.

## Reporting security issues

Do not open a public issue for a security vulnerability. Follow the
reporting process in [`SECURITY.md`](SECURITY.md) instead.
