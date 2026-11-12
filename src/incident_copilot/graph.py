"""Session 13: query scoped, provenance-bearing platform topology snapshots.

Collectors supply normalized facts; this module neither discovers infrastructure
nor infers causality. Configuration and runtime observations remain separate edges.
"""

from collections import deque

from .events import timestamp
from .models import ValidationError
from .rag import retrieve_knowledge
from .remediation import identifier, number, object_fields, positive_integer
from .rollout import fingerprint, identifiers


KINDS = {"Repository", "Service", "Workload", "Cluster", "Database", "CloudResource",
         "TerraformResource", "CrossplaneComposite", "ArgoCDApplication", "Team", "SLO",
         "Incident"}
# Each edge has a fixed direction and typed endpoints. Context edges never carry impact.
RELATIONS = {
    "CALLS": ({"Service"}, {"Service"}),
    "DEPENDS_ON": ({"Service"}, {"Service"}),
    "USES": ({"Service"}, {"Database", "CloudResource"}),
    "DEPLOYS": ({"Repository"}, {"Service", "Workload"}),
    "RUNS_AS": ({"Service"}, {"Workload"}),
    "RUNS_ON": ({"Workload", "Database"}, {"Cluster", "CloudResource"}),
    "MANAGED_BY": ({"Workload", "Database", "CloudResource"},
                   {"ArgoCDApplication", "TerraformResource", "CrossplaneComposite"}),
    "PROVISIONED_BY": ({"Database", "CloudResource"},
                       {"TerraformResource", "CrossplaneComposite"}),
    "MANAGES": ({"TerraformResource", "CrossplaneComposite"}, {"Database", "CloudResource"}),
    "OWNED_BY": ({"Service", "Repository", "Cluster", "Database", "CloudResource",
                  "Workload"}, {"Team"}),
    "HAS_SLO": ({"Service"}, {"SLO"}),
    "AFFECTED": ({"Incident"}, {"Service", "Database", "Cluster", "CloudResource", "Workload"}),
}
FORWARD_IMPACT = {"DEPLOYS", "MANAGES"}
REVERSE_IMPACT = {"CALLS", "DEPENDS_ON", "USES", "RUNS_AS", "RUNS_ON", "MANAGED_BY",
                  "PROVISIONED_BY"}
CONTEXT = {"OWNED_BY", "HAS_SLO", "AFFECTED"}


def _text(value, name):
    """Bound descriptive collector data without granting it authority."""
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 500:
        raise ValidationError(f"{name} must be nonempty text of at most 500 characters")


def _scopes(value):
    """A nonempty scope list avoids accidentally public topology."""
    identifiers(value, "scopes")
    if not value:
        raise ValidationError("scopes must not be empty")


def _snapshot(graph):
    """Reject duplicate identities, dangling links, and invalid relationship semantics."""
    object_fields(graph, {"environment", "nodes", "edges"}, "graph")
    identifier(graph["environment"], "environment")
    if not isinstance(graph["nodes"], list) or not 1 <= len(graph["nodes"]) <= 2000:
        raise ValidationError("graph requires 1 to 2000 nodes")
    if not isinstance(graph["edges"], list) or len(graph["edges"]) > 10000:
        raise ValidationError("graph permits at most 10000 edges")
    nodes = {}
    for node in graph["nodes"]:
        object_fields(node, {"id", "kind", "name", "required_scopes"}, "node")
        identifier(node["id"], "node id")
        if not isinstance(node["kind"], str) or node["kind"] not in KINDS:
            raise ValidationError("unsupported node kind")
        if node["id"] in nodes:
            raise ValidationError("duplicate node id")
        _text(node["name"], "node name")
        if node["kind"] == "Service":
            identifier(node["name"], "service name")
        _scopes(node["required_scopes"])
        nodes[node["id"]] = node
    seen = set()
    for edge in graph["edges"]:
        _edge(edge, nodes)
        if edge["id"] in seen:
            raise ValidationError("duplicate edge id")
        seen.add(edge["id"])
    return nodes


def _edge(edge, nodes):
    """Every independent assertion carries source, observation count, time, and scope."""
    object_fields(edge, {"id", "from", "to", "relationship", "source", "basis", "confidence",
                         "observations", "last_seen", "required_scopes"}, "edge")
    for key in ("id", "from", "to", "source"):
        identifier(edge[key], key)
    relation = edge["relationship"]
    if not isinstance(relation, str) or relation not in RELATIONS:
        raise ValidationError("unsupported relationship")
    if edge["from"] not in nodes or edge["to"] not in nodes or edge["from"] == edge["to"]:
        raise ValidationError("edge requires distinct existing endpoints")
    left, right = RELATIONS[relation]
    if nodes[edge["from"]]["kind"] not in left or nodes[edge["to"]]["kind"] not in right:
        raise ValidationError("relationship endpoint kinds do not match")
    if edge["basis"] not in ("configured", "observed", "historical"):
        raise ValidationError("basis must be configured, observed, or historical")
    if (relation == "AFFECTED") != (edge["basis"] == "historical"):
        raise ValidationError("historical edges must describe incident impact")
    number(edge["confidence"], "confidence", 0, 1)
    positive_integer(edge["observations"], "observations")
    timestamp(edge["last_seen"])
    _scopes(edge["required_scopes"])


def _query(query, graph, nodes):
    """Treat query scopes and clock as adapter-provided authorization and review time."""
    object_fields(query, {"root", "environment", "mode", "as_of", "granted_scopes",
                          "min_confidence", "min_observations", "max_age_seconds",
                          "max_hops", "max_nodes"}, "graph query")
    identifier(query["root"], "root")
    if query["environment"] != graph["environment"]:
        raise ValidationError("graph environment differs from query")
    _scopes(query["granted_scopes"])
    if (query["root"] not in nodes or not set(nodes[query["root"]]["required_scopes"])
            .issubset(query["granted_scopes"])):
        raise ValidationError("root unavailable in authorized graph")
    if query["mode"] not in ("impact", "dependencies"):
        raise ValidationError("mode must be impact or dependencies")
    timestamp(query["as_of"])
    number(query["min_confidence"], "minimum confidence", 0, 1)
    for key in ("min_observations", "max_age_seconds", "max_hops", "max_nodes"):
        positive_integer(query[key], key)
    if query["max_hops"] > 10 or query["max_nodes"] > 500:
        raise ValidationError("query exceeds 10 hops or 500 nodes")


def _eligible_edges(graph, query, nodes):
    """Hide unauthorized facts entirely; explain other exclusions without deleting assertions."""
    scopes = set(query["granted_scopes"])
    visible = {key for key, node in nodes.items() if set(node["required_scopes"]) <= scopes}
    accepted, excluded = [], []
    for edge in sorted(graph["edges"], key=lambda item: item["id"]):
        if (edge["from"] not in visible or edge["to"] not in visible
                or not set(edge["required_scopes"]) <= scopes):
            continue
        age = (timestamp(query["as_of"]) - timestamp(edge["last_seen"])).total_seconds()
        reason = None
        if age < 0:
            reason = "future_observation"
        elif edge["basis"] != "historical" and age > query["max_age_seconds"]:
            reason = "stale_relationship"
        elif edge["confidence"] < query["min_confidence"]:
            reason = "low_confidence"
        elif edge["basis"] == "observed" and edge["observations"] < query["min_observations"]:
            reason = "insufficient_observations"
        if reason:
            excluded.append({"edge_id": edge["id"], "reason": reason})
        else:
            accepted.append(edge)
    return accepted, excluded


def _adjacency(edges, mode):
    """Context is attached after traversal, never used as a propagation shortcut."""
    adjacency = {}
    for edge in edges:
        relation = edge["relationship"]
        if relation in CONTEXT:
            continue
        forward = relation in FORWARD_IMPACT
        if mode == "dependencies":
            forward = not forward
        start, end = (edge["from"], edge["to"]) if forward else (edge["to"], edge["from"])
        adjacency.setdefault(start, []).append((end, edge))
    return adjacency


def _walk(root, adjacency, query):
    """Return deterministic shortest evidence paths, terminating cycles and bounding work."""
    paths = {root: []}
    queue = deque([root])
    truncated = False
    while queue:
        current = queue.popleft()
        for target, edge in adjacency.get(current, []):
            if target in paths:
                continue
            if len(paths[current]) >= query["max_hops"] or len(paths) >= query["max_nodes"]:
                truncated = True
                continue
            paths[target] = paths[current] + [{"edge_id": edge["id"], "from": current,
                                               "to": target}]
            queue.append(target)
    return paths, truncated


def query_graph(graph, query):
    """Build a scoped reasoning packet; an empty neighborhood never proves no impact."""
    nodes = _snapshot(graph)
    _query(query, graph, nodes)
    edges, excluded = _eligible_edges(graph, query, nodes)
    paths, truncated = _walk(query["root"], _adjacency(edges, query["mode"]), query)
    context_edges = [edge for edge in edges if (
        edge["relationship"] in {"OWNED_BY", "HAS_SLO"} and edge["from"] in paths
        or edge["relationship"] == "AFFECTED" and edge["to"] in paths
        or edge["relationship"] == "DEPLOYS" and edge["to"] in paths)]
    context_ids = {endpoint for edge in context_edges for endpoint in (edge["from"], edge["to"])}
    included = set(paths) | context_ids
    # Bound annotations too; never hide result truncation from downstream consumers.
    remaining = query["max_nodes"] - len(paths)
    extra = sorted(included - set(paths))
    if len(extra) > remaining:
        truncated = True
    included = set(paths) | set(extra[:remaining])
    relevant_edges = [edge for edge in edges
                      if edge["from"] in included and edge["to"] in included]
    result = {"decision": "bounded_context" if truncated else "context_available",
              "environment": graph["environment"], "root": query["root"],
              "mode": query["mode"], "as_of": query["as_of"],
              "graph_sha256": fingerprint(graph), "query_sha256": fingerprint(query),
              "truncated": truncated, "coverage": "snapshot_only",
              "nodes": [nodes[key] for key in sorted(included)], "edges": relevant_edges,
              "paths": [{"node_id": key, "steps": steps}
                        for key, steps in sorted(paths.items())],
              "excluded_edges": excluded,
              "retrieval_targets": [{"service": nodes[key]["name"],
                                     "environment": graph["environment"]}
                                    for key in sorted(paths) if nodes[key]["kind"] == "Service"],
              "mutation_authorized": False,
              "limitations": ["Paths show potential dependencies, not demonstrated causality.",
                              "Absent or filtered edges do not prove absence of dependencies.",
                              "Prior incident links do not prove a new change causes recurrence."]}
    result["packet_sha256"] = fingerprint(result)
    return result


def graph_knowledge(graph, query, documents, question):
    """Use graph-selected services with the existing authority and access-aware retriever."""
    _text(question, "question")
    packet = query_graph(graph, query)
    packet["question"] = question
    packet["documents_sha256"] = fingerprint(documents)
    packet["knowledge"] = [{"service": target["service"], "result": retrieve_knowledge({
        "question": question, **target, "as_of": timestamp(query["as_of"]).date().isoformat(),
        "granted_scopes": query["granted_scopes"], "top_k": 5}, documents).to_dict()}
        for target in packet["retrieval_targets"]]
    packet.pop("packet_sha256")
    packet["packet_sha256"] = fingerprint(packet)
    return packet
