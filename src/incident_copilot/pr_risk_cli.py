"""Review a normalized GitOps PR against operational evidence without contacting GitHub."""

import argparse
import json
import sys

from .__main__ import load_json
from .models import ValidationError
from .pr_risk import review_pr_risk


def main():
    """Emit a risk report; failures and missing context produce nonzero status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changes", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--assessment", help="Optional model findings with bound citations")
    args = parser.parse_args()
    try:
        result = review_pr_risk(load_json(args.changes), load_json(args.context),
                                load_json(args.assessment) if args.assessment else None)
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["decision"] in ("block", "investigate") else 0


if __name__ == "__main__":
    raise SystemExit(main())
