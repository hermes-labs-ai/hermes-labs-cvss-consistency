"""Test local prompt preparation and strict saved-answer normalization."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
ADAPTER = ROOT / "benchmark/adapter.py"


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ADAPTER), *args], cwd=ROOT, text=True, capture_output=True)


def test_saved_answers_normalize_and_score_end_to_end(tmp_path: Path) -> None:
    prompts, predictions = tmp_path / "prompts.json", tmp_path / "predictions.json"
    assert invoke("prompts", "--output", str(prompts)).returncode == 0
    prompt_payload = json.loads(prompts.read_text())
    assert len(prompt_payload["cases"]) == 10
    assert [case["id"] for case in prompt_payload["cases"]] == [f"case-{index:02d}" for index in range(1, 11)]
    assert all("expected" not in case for case in prompt_payload["cases"])
    result = invoke("normalize", str(ROOT / "benchmark/examples/sample-structured-answers.json"), "--output", str(predictions))
    assert result.returncode == 0, result.stderr
    score = subprocess.run([sys.executable, str(ROOT / "benchmark/run.py"), "score", str(predictions)], text=True, capture_output=True)
    assert score.returncode == 0, score.stderr
    assert json.loads(score.stdout)["correct"] == 10


@pytest.mark.parametrize("answers, message", [
    ([{"id": "case-01", "label": "mismatch"}], "exactly"),
    ([{"id": "case-01", "label": "mismatch"}] * 2, "duplicate"),
    ([{"id": "case-01", "label": "unknown"}], "label"),
    ([{"id": "case-01", "label": "mismatch", "extra": True}], "exactly"),
])
def test_saved_answers_reject_invalid_or_duplicate_records(tmp_path: Path, answers: list[dict[str, object]], message: str) -> None:
    source, output = tmp_path / "answers.json", tmp_path / "predictions.json"
    source.write_text(json.dumps({"answers": answers}))
    result = invoke("normalize", str(source), "--output", str(output))
    assert result.returncode == 2
    assert message in result.stderr
    assert not output.exists()
