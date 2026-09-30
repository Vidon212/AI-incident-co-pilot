"""Verify a reviewed remediation contract against trusted observation snapshots."""

import argparse
import json
import sys

from .__main__ import load_json
from .models import ValidationError
from .verification import evaluate_verification


def main():
    """Print a deterministic verification artifact without querying production."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--observations", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_verification(load_json(args.intent), load_json(args.observations))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.outcome == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
