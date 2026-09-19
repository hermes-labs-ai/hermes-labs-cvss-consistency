"""Run or score the public CVSS consistency challenge; no network calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("cases.json")
LABELS = ("consistent", "mismatch", "invalid")


def cases():
    return json.loads(MANIFEST.read_text())["cases"]


def reference_predictions():
    from hermes_labs_cvss_consistency.check import check_record

    predictions = {}
    for case in cases():
        record = json.loads((ROOT / case["fixture"]).read_text()) if "fixture" in case else case["record"]
        results = check_record(record)
        statuses = {result["status"] for result in results}
        label = "invalid" if not results or "invalid" in statuses else "mismatch" if "mismatch" in statuses else "consistent"
        predictions[case["id"]] = label
    return predictions


def score(predictions):
    expected = {case["id"]: case["expected"] for case in cases()}
    if not isinstance(predictions, dict) or set(predictions) != set(expected):
        raise ValueError("predictions must contain exactly the published case IDs")
    if any(not isinstance(label, str) or label not in LABELS for label in predictions.values()):
        raise ValueError("each prediction must be consistent, mismatch, or invalid")
    confusion = {actual: {predicted: 0 for predicted in LABELS} for actual in LABELS}
    for key, actual in expected.items():
        confusion[actual][predictions[key]] += 1
    correct = sum(confusion[label][label] for label in LABELS)
    return {"benchmark": "cvss-consistency-v1", "correct": correct, "total": len(expected),
            "accuracy": correct / len(expected), "confusion": confusion,
            "failed_cases": sorted(key for key in expected if predictions[key] != expected[key])}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate prediction ID: {key}")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("reference", "score"))
    parser.add_argument("predictions", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "reference":
            if args.predictions:
                parser.error("reference takes no predictions file")
            output = reference_predictions()
        else:
            if not args.predictions:
                parser.error("score requires a predictions JSON file")
            output = score(json.loads(args.predictions.read_text(), object_pairs_hook=unique_object))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
