"""Review autonomy eligibility from normalized local evidence without executing actions."""

import argparse
import json
import sys

from .__main__ import load_json
from .autonomy import review_autonomy
from .models import ValidationError


def main():
    """Emit a six-level capability review, retaining independent execution boundaries."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("proposal", "context"):
        parser.add_argument(f"--{name}", required=True)
    for name in ("capability-platform", "replay", "impact-bundle"):
        parser.add_argument(f"--{name}")
    args = parser.parse_args()
    try:
        result = review_autonomy(load_json(args.proposal), load_json(args.context),
                                 load_json(args.capability_platform) if args.capability_platform
                                 else None, load_json(args.replay) if args.replay else None,
                                 load_json(args.impact_bundle) if args.impact_bundle else None)
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
