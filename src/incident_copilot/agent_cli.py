"""Review a synthetic platform-agent trace without invoking any external tool."""

import argparse
import json
import sys

from .__main__ import load_json
from .agent import evaluate_agent_run
from .models import ValidationError


def main():
    """Print an auditable tool-trace decision without executing its proposal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--plan")
    args = parser.parse_args()
    try:
        plan = load_json(args.plan) if args.plan else None
        result = evaluate_agent_run(load_json(args.context), load_json(args.run), plan)
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.decision in {"requires_plan", "requires_human_approval"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
