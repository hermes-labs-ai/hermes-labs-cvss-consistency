"""Command-line interface for Hermes Labs CVSS Consistency."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .check import DEPENDENCY_VERSION, check_record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check local CVE JSON CVSS v3 scores against their vectors.")
    parser.add_argument("input", nargs="+", type=Path, help="one or more local JSON files")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    return parser


def _records(value: Any) -> list[dict[str, Any]]:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, dict) for item in values):
        raise ValueError("input must be a CVE JSON object or a non-empty array of objects")
    return values


def run(paths: list[Path]) -> tuple[dict[str, Any], int]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in paths:
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {token}")),
            )
            file_results: list[dict[str, Any]] = []
            for record_index, record in enumerate(_records(value)):
                record_results = check_record(record)
                for result in record_results:
                    result["record_index"] = record_index
                file_results.extend(record_results)
            if not file_results:
                raise ValueError("no supported cvssV3_0 or cvssV3_1 metric found")
            for result in file_results:
                result["input"] = str(path)
            results.extend(file_results)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append({"error": f"{type(exc).__name__}: {exc}", "input": str(path)})

    results.sort(key=lambda item: (item["input"], item["json_path"], item["metric_version"]))
    errors.sort(key=lambda item: item["input"])
    payload = {
        "dependency": {"name": "cvss", "version": DEPENDENCY_VERSION},
        "errors": errors,
        "results": results,
        "schema_version": 1,
        "tool": "hermes-labs-cvss-consistency",
        "tool_version": __version__,
    }
    if errors or any(item["status"] == "invalid" for item in results):
        return payload, 2
    if any(item["status"] == "mismatch" for item in results):
        return payload, 1
    return payload, 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload, exit_code = run(args.input)
    if args.format == "json":
        print(json.dumps(payload, allow_nan=False, indent=2, sort_keys=True))
    else:
        for result in payload["results"]:
            print(f"{result['status']:10} {result['cve_id'] or '-'} {result['metric_version']} {result['stated_score']} -> {result['computed_score']} {result['json_path']}")
        for error in payload["errors"]:
            print(f"error      {error['input']}: {error['error']}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
