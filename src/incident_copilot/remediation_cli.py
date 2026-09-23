"""Read-only CLI for Session 3 remediation safety evaluation."""

import argparse
import json
import sys

from .__main__ import load_json
from .models import ValidationError
from .remediation import evaluate_remediation


def main():
    """Evaluate local evidence and print a review artifact, without side effects."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--plan")
    args = parser.parse_args()
    try:
        result = evaluate_remediation(
            load_json(args.intent), load_json(args.context),
            load_json(args.plan) if args.plan else None,
        )
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 1 if result.decision in ("deny", "investigate") else 0


if __name__ == "__main__":
    raise SystemExit(main())
