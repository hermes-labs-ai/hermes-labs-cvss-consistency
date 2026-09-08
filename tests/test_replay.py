import hashlib
import json
from pathlib import Path

import pytest

from hermes_labs_cvss_consistency.__main__ import run


ROOT = Path(__file__).parents[1]
BEFORE = ROOT / "fixtures" / "CVE-2026-14216.before.json"
AFTER = ROOT / "fixtures" / "CVE-2026-14216.after.json"


def test_before_replays_single_cisa_adp_mismatch() -> None:
    payload, exit_code = run([BEFORE])

    assert exit_code == 1
    assert len(payload["results"]) == 1
    result = payload["results"][0]
    assert result["status"] == "mismatch"
    assert result["stated_score"] == 5.3
    assert result["computed_score"] == 6.5
    assert result["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    assert result["json_path"] == "/containers/adp/0/metrics/0/cvssV3_1"
    assert result["metric_source"] == {
        "container": "adp",
        "index": 0,
        "org_id": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
        "short_name": "CISA-ADP",
    }


def test_after_replays_corrected_score() -> None:
    payload, exit_code = run([AFTER])

    assert exit_code == 0
    assert [(item["status"], item["computed_score"]) for item in payload["results"]] == [("consistent", 6.5)]


def test_json_payload_and_fixture_hashes_are_stable() -> None:
    first, _ = run([BEFORE, AFTER])
    second, _ = run([BEFORE, AFTER])
    assert json.dumps(first, indent=2, sort_keys=True) == json.dumps(second, indent=2, sort_keys=True)

    provenance = json.loads((ROOT / "fixtures" / "provenance.json").read_text())
    for name, details in provenance["fixtures"].items():
        assert hashlib.sha256((ROOT / "fixtures" / name).read_bytes()).hexdigest() == details["fixture_sha256"]


@pytest.mark.parametrize("content", ["{", '{"cveMetadata":{"cveId":"CVE-2026-1"}}'])
def test_malformed_or_no_metric_exits_two(tmp_path: Path, content: str) -> None:
    path = tmp_path / "input.json"
    path.write_text(content)
    payload, exit_code = run([path])
    assert exit_code == 2
    assert payload["errors"]


def test_invalid_metric_shapes_and_nonfinite_json_exit_two(tmp_path: Path) -> None:
    malformed_metric = tmp_path / "malformed-metric.json"
    malformed_metric.write_text(json.dumps({"cveMetadata": None, "containers": {"cna": {"providerMetadata": None, "metrics": [{"cvssV3_1": []}]}}}))
    payload, exit_code = run([malformed_metric])
    assert exit_code == 2
    assert payload["results"][0]["status"] == "invalid"
    assert payload["results"][0]["metric_source"]["container"] == "cna"
    json.dumps(payload, allow_nan=False)

    boolean_score = tmp_path / "boolean-score.json"
    boolean_score.write_text(json.dumps({"metrics": [{"cvssV3_1": {"baseScore": True, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"}}]}))
    payload, exit_code = run([boolean_score])
    assert exit_code == 2
    assert payload["results"][0]["status"] == "invalid"

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"metrics":[{"cvssV3_1":{"baseScore":NaN,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"}}]}')
    payload, exit_code = run([nonfinite])
    assert exit_code == 2
    assert payload["errors"][0]["error"].endswith("invalid JSON constant: NaN")
