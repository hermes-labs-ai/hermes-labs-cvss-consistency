"""Adapt the existing fixed-manifest scorer to GitHub Actions outputs."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from run import score, unique_object


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', required=True, type=Path)
    parser.add_argument('--fail-on-mismatch', choices=('true', 'false'), default='false')
    args = parser.parse_args()
    try:
        with args.predictions.open('rb') as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError('predictions exceed 64 KiB')
        predictions = json.loads(raw, object_pairs_hook=unique_object)
        result = score(predictions)
    except (OSError, ValueError):
        print('::error::Predictions must be valid JSON with exactly the published case IDs and labels.')
        return 2
    receipt = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if len(receipt.encode()) > 65536:
        print('::error::Score receipt exceeded the output bound.')
        return 2
    with tempfile.NamedTemporaryFile(mode='w', prefix='cvss-score-', suffix='.json',
                                     dir=os.environ['RUNNER_TEMP'], delete=False) as artifact:
        artifact.write(receipt)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'receipt<<CVSS_RECEIPT\n{receipt}CVSS_RECEIPT\n')
        output.write(f'artifact-path={artifact.name}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write('## CVSS consistency starter benchmark\n\n')
        summary.write(f"{result['correct']} of {result['total']} published cases matched.\n\n")
        summary.write('This fixed ten-case exercise does not establish general accuracy, '
                      'tool rankings, or reproduction of the original corpus audit.\n\n')
        summary.write(f'```json\n{receipt}```\n')
    return int(args.fail_on_mismatch == 'true' and bool(result['failed_cases']))


if __name__ == '__main__':
    raise SystemExit(main())
