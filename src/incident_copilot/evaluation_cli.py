"""Compare recorded candidate and baseline agent runs on a reviewed incident dataset."""

import argparse
import json
import sys

from .__main__ import load_json
from .evaluation import evaluate_versions
from .models import ValidationError


def main():
    """Emit metrics, structured provenance, and a deterministic promotion decision."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("dataset", "candidate", "baseline", "policy"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_versions(load_json(args.dataset), load_json(args.candidate),
                                   load_json(args.baseline), load_json(args.policy))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["decision"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
