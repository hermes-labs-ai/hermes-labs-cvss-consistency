"""Prepare provider-neutral challenge prompts and normalize saved answers.

This utility never calls a model or a provider.  It only creates local input
records and converts saved structured answers into the predictions JSON that
the existing scorer accepts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from run import LABELS, cases, unique_object


ROOT = Path(__file__).resolve().parents[1]
INSTRUCTION = (
    "Classify this stored CVSS 3.1 record as consistent, mismatch, or invalid. "
    "Return exactly one JSON object with its supplied id and one label."
)


def prompt_records() -> list[dict[str, object]]:
    """Return provider-neutral per-case inputs without published answer labels."""
    records: list[dict[str, object]] = []
    for index, case in enumerate(cases(), start=1):
        record = json.loads((ROOT / case["fixture"]).read_text()) if "fixture" in case else case["record"]
        records.append({"id": f"case-{index:02d}", "instruction": INSTRUCTION, "record": record})
    return records


def normalized_predictions(payload: object) -> dict[str, str]:
    """Validate saved answer records and return the scorer's predictions object."""
    answers = payload.get("answers") if isinstance(payload, dict) else payload
    if not isinstance(answers, list):
        raise ValueError("saved answers must be a JSON array or an object with an answers array")
    case_ids = [case["id"] for case in cases()]
    prompt_ids = [f"case-{index:02d}" for index in range(1, len(case_ids) + 1)]
    expected_ids = set(prompt_ids)
    predictions: dict[str, str] = {}
    for answer in answers:
        if not isinstance(answer, dict) or set(answer) != {"id", "label"}:
            raise ValueError("each saved answer must contain exactly id and label")
        case_id, label = answer["id"], answer["label"]
        if not isinstance(case_id, str) or not isinstance(label, str):
            raise ValueError("each saved answer id and label must be strings")
        if case_id in predictions:
            raise ValueError(f"duplicate answer ID: {case_id}")
        if label not in LABELS:
            raise ValueError("each saved answer label must be consistent, mismatch, or invalid")
        predictions[case_id] = label
    if set(predictions) != expected_ids:
        raise ValueError("saved answers must contain exactly the published case IDs")
    return {case_id: predictions[prompt_id] for case_id, prompt_id in zip(case_ids, prompt_ids)}


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prompts = subparsers.add_parser("prompts", help="write provider-neutral per-case prompt records")
    prompts.add_argument("--output", required=True, type=Path)
    normalize = subparsers.add_parser("normalize", help="convert saved structured answers to predictions JSON")
    normalize.add_argument("answers", type=Path)
    normalize.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prompts":
            args.output.write_text(json.dumps({"cases": prompt_records()}, indent=2) + "\n", encoding="utf-8")
        else:
            args.output.write_text(json.dumps(normalized_predictions(read_json(args.answers)), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
