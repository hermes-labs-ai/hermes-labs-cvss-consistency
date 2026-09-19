"""Challenge scoring must not silently omit difficult or missing cases."""
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("benchmark_run", Path(__file__).parents[1] / "benchmark/run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_reference_matches_published_labels():
    result = runner.score(runner.reference_predictions())
    assert result["correct"] == result["total"] == 10
    assert result["failed_cases"] == []


def test_constant_answer_cannot_hide_mismatches_and_invalid_cases():
    result = runner.score({case["id"]: "consistent" for case in runner.cases()})
    assert result["correct"] == 3
    assert result["total"] == 10
    assert result["confusion"]["mismatch"]["consistent"] == 3
    assert result["confusion"]["invalid"]["consistent"] == 4
    assert len(result["failed_cases"]) == 7


@pytest.mark.parametrize("mutation", ["missing", "extra", "bad-label"])
def test_invalid_submission_is_rejected(mutation):
    predictions = {case["id"]: case["expected"] for case in runner.cases()}
    if mutation == "missing":
        predictions.pop("public-before")
    elif mutation == "extra":
        predictions["extra"] = "consistent"
    else:
        predictions["public-before"] = "unknown"
    with pytest.raises(ValueError):
        runner.score(predictions)


def test_duplicate_ids_are_rejected_before_scoring():
    with pytest.raises(ValueError, match="duplicate"):
        json.loads('{"public-before":"mismatch","public-before":"consistent"}', object_pairs_hook=runner.unique_object)
