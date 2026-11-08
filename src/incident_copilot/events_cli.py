"""Replay normalized incident events into a durable local state machine."""

import argparse
import json
import sqlite3
import sys

from .__main__ import load_json
from .event_orchestrator import EventOrchestrator
from .models import ValidationError
from .remediation import object_fields


def main():
    """Print acknowledgments and pending work; never invoke production or an LLM."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--deliveries", required=True)
    parser.add_argument("--state", required=True, help="SQLite path; :memory: is ephemeral")
    parser.add_argument("--sweep-at", help="Sweep expired investigations at this trusted ISO time")
    args = parser.parse_args()
    store = None
    try:
        context, deliveries = load_json(args.context), load_json(args.deliveries)
        if not isinstance(deliveries, list) or not deliveries:
            raise ValidationError("deliveries must be a nonempty list")
        store = EventOrchestrator(args.state, context)
        receipts, incident_ids = [], set()
        for delivery in deliveries:
            object_fields(delivery, {"event", "principal", "received_at"}, "delivery")
            receipts.append(store.process(delivery["event"], delivery["principal"],
                                          delivery["received_at"]))
            incident_ids.add(delivery["event"]["incident_id"])
        if args.sweep_at:
            store.expire(args.sweep_at)
        result = {"receipts": receipts, "incidents": [store.incident(key)
                                                       for key in sorted(incident_ids)],
                  "pending_outbox": store.pending_outbox(), "audit": store.audit()}
    except (OSError, ValueError, ValidationError, sqlite3.Error) as error:
        print(f"Replay rejected: {error}", file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()
    print(json.dumps(result, indent=2))
    if any(receipt["decision"] in {"retry", "dead_letter"} for receipt in receipts):
        return 1
    return 1 if any(state and state["phase"] in {"escalated", "verification_failed"}
                    for state in result["incidents"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
