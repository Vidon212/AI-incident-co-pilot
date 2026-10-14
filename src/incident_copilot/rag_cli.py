"""Build a policy-filtered platform knowledge packet from local JSON fixtures."""

import argparse
import json
import sys

from .__main__ import load_json
from .models import ValidationError
from .rag import retrieve_knowledge


def main():
    """Print grounded sources without invoking a model or production system."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", required=True)
    parser.add_argument("--documents", required=True)
    args = parser.parse_args()
    try:
        result = retrieve_knowledge(load_json(args.query), load_json(args.documents))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.decision == "grounded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
