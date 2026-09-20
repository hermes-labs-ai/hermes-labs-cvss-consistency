"""Exercise the caller-facing Action adapter, including mismatch exit policy."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CASES = json.loads((ROOT / 'benchmark/cases.json').read_text())['cases']


@pytest.mark.parametrize(('wrong', 'fail', 'expected'), [(False, 'true', 0),
                                                        (True, 'false', 0),
                                                        (True, 'true', 1)])
def test_action_receipt_and_mismatch_policy(tmp_path, wrong, fail, expected):
    predictions = {case['id']: 'consistent' if wrong else case['expected'] for case in CASES}
    source = tmp_path / 'caller predictions.json'
    source.write_text(json.dumps(predictions))
    output, summary = tmp_path / 'outputs', tmp_path / 'summary'
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(output),
               GITHUB_STEP_SUMMARY=str(summary))
    result = subprocess.run([sys.executable, str(ROOT / 'benchmark/action_score.py'),
                             '--predictions', str(source), '--fail-on-mismatch', fail],
                            env=env, capture_output=True, text=True)
    assert result.returncode == expected, result.stderr
    artifact = Path(output.read_text().split('artifact-path=')[1].strip())
    receipt = json.loads(artifact.read_text())
    assert receipt['correct'] == (3 if wrong else 10)
    assert receipt['total'] == 10
    assert 'does not establish general accuracy' in summary.read_text()
    assert artifact.read_text() in output.read_text()


@pytest.mark.parametrize("payload", ['{"unexpected": "invalid"}', " " * 65537])
def test_action_rejects_invalid_predictions_without_outputs(tmp_path, payload):
    source = tmp_path / 'predictions.json'
    source.write_text(payload)
    output, summary = tmp_path / 'outputs', tmp_path / 'summary'
    result = subprocess.run([sys.executable, str(ROOT / 'benchmark/action_score.py'),
                             '--predictions', str(source)], capture_output=True,
                            env=dict(os.environ, RUNNER_TEMP=str(tmp_path),
                                     GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary)))
    assert result.returncode == 2
    assert not output.exists()
    assert not summary.exists()
