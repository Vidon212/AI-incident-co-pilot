"""Screen a normalized infrastructure change and optionally compare a recorded outcome."""

import argparse
import json
import sys

from .__main__ import load_json
from .impact import compare_outcome, simulate_change
from .models import ValidationError
from .rollout import fingerprint


def main():
    """Emit deterministic capacity and impact findings without model or infrastructure calls."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("change", "context", "graph"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--assessment", help="Optional recorded evidence-bound model explanation")
    parser.add_argument("--outcome", help="Optional independent post-change observations")
    args = parser.parse_args()
    try:
        report = simulate_change(load_json(args.change), load_json(args.context),
                                 load_json(args.graph),
                                 load_json(args.assessment) if args.assessment else None)
        if args.outcome:
            report["outcome_comparison"] = compare_outcome(report, load_json(args.outcome))
            report.pop("report_sha256")
            report["report_sha256"] = fingerprint(report)
    except (OSError, ValueError, OverflowError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, allow_nan=False))
    return 1 if report["decision"] in ("block", "investigate") else 0


if __name__ == "__main__":
    raise SystemExit(main())
