"""Command line entry point for a provider-neutral incident context pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .context_pipeline import build_incident_context
from .models import ValidationError


def main() -> int:
    """Normalize collector output and print incident context as JSON."""
    parser = argparse.ArgumentParser(
        description="Normalize and rank incident evidence for LLM reasoning."
    )
    parser.add_argument("--input", required=True, help="Path to trusted collector output as JSON.")
    args = parser.parse_args()
    try:
        with Path(args.input).open(encoding="utf-8") as file:
            print(json.dumps(build_incident_context(json.load(file)), indent=2))
        return 0
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        print(f"Input rejected: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
