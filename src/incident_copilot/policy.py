"""Deterministic authority layer. This module never changes a cluster."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from .models import Diagnosis, IncidentContext


Decision = Literal["investigate", "requires_human_approval", "no_change"]


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    proposed_git_change: dict[str, str] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate(context: IncidentContext, diagnosis: Diagnosis, confidence_threshold: float = 0.80) -> PolicyResult:
    """Apply a deliberately narrow, auditable policy to untrusted diagnosis data."""
    if diagnosis.service != context.service:
        return PolicyResult("no_change", "Diagnosis service does not match incident context.")
    if diagnosis.confidence < confidence_threshold:
        return PolicyResult("investigate", f"Confidence {diagnosis.confidence:.2f} is below {confidence_threshold:.2f}.")
    if diagnosis.recommended_action == "rollback":
        return PolicyResult(
            "requires_human_approval",
            "Rollback recommendations must be approved by a human before a GitOps PR is created.",
            {
                "path": f"apps/{context.namespace}/{context.deployment}/values.yaml",
                "image.tag": context.previous_image_tag,
                "from_image_tag": context.current_image_tag,
            },
        )
    if diagnosis.recommended_action == "investigate":
        return PolicyResult("investigate", "Diagnosis recommends gathering more evidence.")
    return PolicyResult("no_change", "No permitted remediation was recommended.")
