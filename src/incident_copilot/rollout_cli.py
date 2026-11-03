"""Review staged agent promotion and a scoped HPA capability using local JSON."""

import argparse
import json
import sys

from .__main__ import load_json
from .capability import review_capability
from .models import ValidationError
from .rollout import review_rollout


def main():
    """Emit eligibility artifacts, without contacting a deployment or production API."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    promotion = commands.add_parser("promotion")
    for name in ("context", "request", "replay"):
        promotion.add_argument(f"--{name}", required=True)
    capability = commands.add_parser("capability")
    for name in ("platform", "intent", "plan", "replay"):
        capability.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        if args.command == "promotion":
            result = review_rollout(load_json(args.context), load_json(args.request),
                                    load_json(args.replay))
        else:
            result = review_capability(load_json(args.platform), load_json(args.intent),
                                       load_json(args.plan), load_json(args.replay))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["decision"] in {
        "eligible_for_next_stage", "eligible_for_preapproved_gitops"
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
