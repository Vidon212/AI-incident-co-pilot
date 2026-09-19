"""Evaluate structured diagnosis output without granting operational authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import Diagnosis, IncidentContext, ValidationError
from .policy import evaluate


def load_json(path: str) -> dict:
    with Path(path).open(encoding="utf-8") as file:
        return json.load(file)


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply deterministic policy to an AI incident diagnosis.")
    parser.add_argument("--context", required=True, help="Path to read-only incident context JSON.")
    parser.add_argument("--diagnosis", required=True, help="Path to schema-constrained model diagnosis JSON.")
    args = parser.parse_args()
    try:
        context = IncidentContext.from_dict(load_json(args.context))
        diagnosis = Diagnosis.from_dict(load_json(args.diagnosis))
        print(json.dumps(evaluate(context, diagnosis).to_dict(), indent=2))
        return 0
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        print(f"Input rejected: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
