"""Review a multi-hypothesis incident investigation from local JSON files."""

import argparse
import json
import sys

from .__main__ import load_json
from .investigation import evaluate_investigation
from .models import ValidationError


def main():
    """Print an investigation review artifact without executing a remediation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_investigation(load_json(args.context), load_json(args.run))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.decision == "ready_for_remediation_review" else 1


if __name__ == "__main__":
    raise SystemExit(main())
