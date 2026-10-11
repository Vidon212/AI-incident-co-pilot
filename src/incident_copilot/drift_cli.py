"""Review an AI drift assessment against trusted provenance and resource semantics."""

import argparse
import json
import sys

from .__main__ import load_json
from .drift import evaluate_drift
from .models import ValidationError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True)
    parser.add_argument("--assessment", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_drift(load_json(args.record), load_json(args.assessment))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.decision in {"no_action", "requires_human_approval"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
