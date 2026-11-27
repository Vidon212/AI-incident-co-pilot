"""Replay Kubernetes-shaped resource reconciliation locally; never contact a cluster."""

from copy import deepcopy
import argparse
import json
import sqlite3
import sys

from .__main__ import load_json
from .models import ValidationError
from .reliability_controller import ReliabilityController
from .remediation import object_fields


def main():
    """Persist status and stable outbox requests across restarts of a synthetic replay."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("platform", "scenario", "review-context", "capability-platform", "replay",
                 "state"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    store = None
    try:
        scenario = load_json(args.scenario)
        object_fields(scenario, {"resources", "frames"}, "scenario")
        if not isinstance(scenario["resources"], list) or not isinstance(scenario["frames"], list):
            raise ValidationError("scenario resources and frames must be lists")
        sources = {"context": load_json(args.review_context),
                   "capabilityPlatform": load_json(args.capability_platform),
                   "replay": load_json(args.replay)}
        store = ReliabilityController(args.state, load_json(args.platform))
        for resource in scenario["resources"]:
            store.register(resource)
        receipts = []
        for raw in scenario["frames"]:
            frame = deepcopy(raw)
            if frame.get("event") == "review" and frame.get("payload") == {}:
                frame["payload"] = sources
            receipts.append(store.reconcile(frame))
        result = {"receipts": receipts, "resources": store.resources(),
                  "pending_work": store.pending_work(), "execution_authorized": False}
    except (OSError, ValueError, ValidationError, sqlite3.Error) as error:
        print(f"Reconciliation rejected: {error}", file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()
    print(json.dumps(result, indent=2))
    return 1 if any(item["status"]["phase"] in {"Escalated", "Failed", "Denied"}
                    for item in result["resources"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
