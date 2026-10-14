"""Deterministic retrieval policy for a grounded platform copilot.

External search supplies candidate similarity. This module validates metadata,
enforces caller scopes, ranks organizational authority and freshness, and emits
only reviewed structured facts with citations. Raw document content remains
untrusted and is never copied into the reasoning packet.
"""

from dataclasses import asdict, dataclass, fields
from datetime import date
import json

from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer


DOCUMENT_TYPES = {
    "platform-standard", "architecture-decision", "composition", "terraform-module",
    "runbook", "service-metadata", "runtime-recommendation", "postmortem",
    "debug-note", "chat",
}
STATUSES = {"approved", "current", "observed", "historical", "draft", "deprecated"}
FACT_KINDS = {"requirement", "implementation", "operational", "historical",
              "recommendation", "ownership"}
AUTHORITY = {
    "platform-standard": 1.00,
    "architecture-decision": 0.95,
    "composition": 0.90,
    "terraform-module": 0.85,
    "runbook": 0.90,
    "service-metadata": 0.85,
    "runtime-recommendation": 0.75,
    "postmortem": 0.60,
    "debug-note": 0.20,
    "chat": 0.10,
}
STATUS_WEIGHT = {
    "approved": 1.00,
    "current": 0.95,
    "observed": 0.90,
    "historical": 0.70,
    "draft": 0.35,
    "deprecated": 0.00,
}
MINIMUM_SCORE = 0.15
CONTRADICTION_SCORE = 0.45


def _text(value, name):
    """Require nonempty text without assigning it authority."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a nonempty string")


def _date(value, name):
    """Parse an ISO calendar date."""
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValidationError(f"{name} must be an ISO date") from error


def _scopes(value, name):
    """Validate a duplicate-free list of authorization scope identifiers."""
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise ValidationError(f"{name} must be a duplicate-free list")
    for scope in value:
        identifier(scope, f"{name} scope")


def _fact_value(value, name):
    """Limit reviewed facts to auditable scalar values."""
    if type(value) not in (str, int, float, bool):
        raise ValidationError(f"{name} must be a scalar")
    if isinstance(value, str):
        _text(value, name)
    elif type(value) in (int, float):
        number(value, name)


@dataclass(frozen=True)
class RetrievalQuery:
    """Question metadata and externally authenticated access scopes."""

    question: str
    service: str
    environment: str
    as_of: str
    granted_scopes: list[str]
    top_k: int

    @classmethod
    def from_dict(cls, raw):
        """Validate a query without treating its text as policy."""
        object_fields(raw, [field.name for field in fields(cls)], "query")
        _text(raw["question"], "question")
        for key in ("service", "environment"):
            identifier(raw[key], key)
        _date(raw["as_of"], "as_of")
        _scopes(raw["granted_scopes"], "granted_scopes")
        positive_integer(raw["top_k"], "top_k")
        if raw["top_k"] > 10:
            raise ValidationError("top_k exceeds 10")
        return cls(**raw)


@dataclass(frozen=True)
class KnowledgeDocument:
    """Normalized retrieval candidate with trusted metadata and reviewed facts."""

    id: str
    title: str
    type: str
    service: str
    environment: str
    team: str
    version: str
    status: str
    last_reviewed: str
    required_scopes: list[str]
    similarity: float
    production_adoption: float
    content: str
    facts: list[dict]

    @classmethod
    def from_dict(cls, raw):
        """Validate metadata separately from untrusted raw content."""
        object_fields(raw, [field.name for field in fields(cls)], "document")
        for key in ("id", "service", "environment", "team", "version"):
            identifier(raw[key], f"document.{key}")
        _text(raw["title"], "document.title")
        _text(raw["content"], "document.content")
        if raw["type"] not in DOCUMENT_TYPES:
            raise ValidationError("document.type is not supported")
        if raw["status"] not in STATUSES:
            raise ValidationError("document.status is not supported")
        _date(raw["last_reviewed"], "document.last_reviewed")
        _scopes(raw["required_scopes"], "document.required_scopes")
        number(raw["similarity"], "document.similarity", 0, 1)
        number(raw["production_adoption"], "document.production_adoption", 0, 1)
        if not isinstance(raw["facts"], list) or not raw["facts"]:
            raise ValidationError("document.facts must contain reviewed facts")
        for fact in raw["facts"]:
            object_fields(fact, {"topic", "value", "kind"}, "document fact")
            identifier(fact["topic"], "document fact topic")
            _fact_value(fact["value"], "document fact value")
            if fact["kind"] not in FACT_KINDS:
                raise ValidationError("document fact kind is not supported")
        return cls(**raw)


@dataclass(frozen=True)
class RetrievalResult:
    """Citation-bearing context packet suitable for downstream reasoning."""

    decision: str
    question: str
    sources: list[dict]
    contradictions: list[dict]
    excluded: list[dict]
    security_notes: list[str]

    def to_dict(self):
        """Return the serializable context packet."""
        return asdict(self)


def _freshness(reviewed, as_of):
    """Apply a bounded freshness factor without erasing historical evidence."""
    age = (as_of - reviewed).days
    if age < 0:
        raise ValidationError("document.last_reviewed cannot be after query.as_of")
    if age <= 90:
        return 1.0
    if age <= 365:
        return 0.9
    if age <= 730:
        return 0.75
    return 0.5


def _eligibility(query, document):
    """Enforce authorization and metadata filters before ranking."""
    if document.status == "deprecated":
        return "deprecated"
    if not set(document.required_scopes).issubset(query.granted_scopes):
        return "access_denied"
    if document.service not in {query.service, "all"}:
        return "service_mismatch"
    if document.environment not in {query.environment, "all"}:
        return "environment_mismatch"
    return None


def _score(query, document):
    """Combine similarity, authority, freshness, context match, and adoption."""
    authority = min(1.0, AUTHORITY[document.type] + document.production_adoption * 0.1)
    service_match = 1.0 if document.service == query.service else 0.85
    environment_match = 1.0 if document.environment == query.environment else 0.85
    freshness = _freshness(_date(document.last_reviewed, "document.last_reviewed"),
                           _date(query.as_of, "query.as_of"))
    return round(document.similarity * authority * STATUS_WEIGHT[document.status]
                 * freshness * service_match * environment_match, 6)


def _citation(document):
    """Create a stable human-readable source reference."""
    return f"{document.id}@{document.version} ({document.last_reviewed})"


def _find_contradictions(sources):
    """Surface conflicting high-authority facts instead of choosing silently."""
    by_topic = {}
    for source in sources:
        if source["score"] < CONTRADICTION_SCORE:
            continue
        for fact in source["facts"]:
            key = json.dumps(fact["value"], sort_keys=True)
            by_topic.setdefault(fact["topic"], {}).setdefault(key, []).append(
                source["citation"]
            )
    contradictions = []
    for topic, values in sorted(by_topic.items()):
        if len(values) > 1:
            contradictions.append({
                "topic": topic,
                "values": [
                    {"value": json.loads(value), "citations": citations}
                    for value, citations in sorted(values.items())
                ],
            })
    return contradictions


def retrieve_knowledge(raw_query, raw_documents):
    """Build a policy-filtered, citation-bearing organizational context packet."""
    query = RetrievalQuery.from_dict(raw_query)
    if not isinstance(raw_documents, list):
        raise ValidationError("documents must be a list")
    documents = [KnowledgeDocument.from_dict(raw) for raw in raw_documents]
    if len({document.id for document in documents}) != len(documents):
        raise ValidationError("document ids must be unique")
    as_of = _date(query.as_of, "query.as_of")
    for document in documents:
        _freshness(_date(document.last_reviewed, "document.last_reviewed"), as_of)

    ranked, excluded = [], []
    for document in documents:
        reason = _eligibility(query, document)
        if reason:
            excluded.append({"id": document.id, "reason": reason})
            continue
        score = _score(query, document)
        if score < MINIMUM_SCORE:
            excluded.append({"id": document.id, "reason": "below_authority_threshold"})
            continue
        ranked.append((score, document))
    ranked.sort(key=lambda item: (-item[0], item[1].id))
    sources = [
        {
            "id": document.id,
            "title": document.title,
            "type": document.type,
            "score": score,
            "citation": _citation(document),
            "facts": document.facts,
        }
        for score, document in ranked[:query.top_k]
    ]
    contradictions = _find_contradictions(sources)
    if contradictions:
        decision = "investigate"
    elif sources:
        decision = "grounded"
    else:
        decision = "insufficient_context"
    return RetrievalResult(
        decision=decision,
        question=query.question,
        sources=sources,
        contradictions=contradictions,
        excluded=excluded,
        security_notes=[
            "Raw retrieved content is untrusted and was excluded from this context packet.",
            "Citations provide evidence only; downstream intent still requires "
            "policy and approval.",
        ],
    )
