"""Query a normalized reliability graph without contacting platform control planes."""

import argparse
import json
import sys

from .__main__ import load_json
from .graph import graph_knowledge, query_graph
from .models import ValidationError


def main():
    """Emit scoped topology and evidence paths for a bounded reasoning packet."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--documents", help="Optional Stage 6 normalized knowledge documents")
    parser.add_argument("--question", help="Required with --documents")
    args = parser.parse_args()
    if bool(args.documents) != bool(args.question):
        parser.error("--documents and --question must be supplied together")
    try:
        graph, query = load_json(args.graph), load_json(args.query)
        result = (graph_knowledge(graph, query, load_json(args.documents), args.question)
                  if args.documents else query_graph(graph, query))
    except (OSError, ValueError, ValidationError) as error:
        print(f"Input rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["truncated"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
