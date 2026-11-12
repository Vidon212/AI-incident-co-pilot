# Stage 13: Platform Reliability Knowledge Graph

[Back to README](../README.md)

Session 13 makes platform relationships queryable before reasoning begins. The
local implementation consumes a normalized topology snapshot and returns scoped
nodes, relationship evidence, shortest paths, owners, SLO nodes, repository links,
and historical incidents. It can then retrieve cited organizational knowledge for
the services reached by the graph using the existing Stage 6 policy.

## Run the examples

```bash
make graph PYTHON=.venv/bin/python
make graph-rag PYTHON=.venv/bin/python

# Investigate a service's dependencies instead of an infrastructure change's impact.
PYTHONPATH=src .venv/bin/python -m incident_copilot.graph_cli \
  --graph examples/graph/platform.json \
  --query examples/graph/checkout-dependencies.json
```

The impact example starts at `inventory-tf` and produces this evidence path:

```text
inventory-tf → inventory-sql → inventory-db → inventory-api → checkout-api
```

It attaches inventory and commerce owners, the checkout SLO node, the deploying
repository, and incident `INC-892`. The dependency example starts at checkout and
follows its inventory, pricing, and identity calls, workload, cluster, and owning
control paths. A two-observation, low-confidence debug call is excluded. These
synthetic snapshots need no credentials, model key, graph server, or cloud access.

For Docker, build the existing image and run the same module and paths:

```bash
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges ai-incident-copilot:local \
  incident_copilot.graph_cli --graph examples/graph/platform.json \
  --query examples/graph/database-impact.json
```

## Snapshot contract

Each graph belongs to one environment. Node IDs are unique within that snapshot;
live adapters must derive stable, unambiguous IDs from full resource identities,
including project, cluster, namespace, and provider identity where applicable.
Display names must not serve as infrastructure identity. Service names are the
catalog keys used by Stage 6 retrieval. Nodes carry kind, name, and required access
scopes. Relationship endpoints must exist and match the allowed kinds.

| Relationship | Direction in the snapshot | Use |
| --- | --- | --- |
| `CALLS`, `DEPENDS_ON` | Service → Service | Runtime/configured dependencies |
| `USES` | Service → Database or CloudResource | Data/resource dependency |
| `DEPLOYS` | Repository → Service or Workload | Git ownership path |
| `RUNS_AS` | Service → Workload | Workload mapping |
| `RUNS_ON` | Workload or Database → Cluster or CloudResource | Hosting dependency |
| `MANAGED_BY`, `PROVISIONED_BY` | Workload/Database/CloudResource → allowed controller/IaC node | Authoritative control path |
| `MANAGES` | TerraformResource or CrossplaneComposite → Database or CloudResource | Alternative forward ownership mapping |
| `OWNED_BY` | Supported resource or service → Team | Context annotation |
| `HAS_SLO` | Service → SLO | Context annotation |
| `AFFECTED` | Incident → Service/Database/Cluster/CloudResource/Workload | Historical context annotation |

See `RELATIONS` in [graph.py](../src/incident_copilot/graph.py) for exact endpoint
kinds. The contract is intentionally narrow; unknown kinds, relationships, fields,
duplicate IDs, self-links, and dangling endpoints are rejected.

Each edge includes `id`, `from`, `to`, `relationship`, `source`, `basis`,
`confidence`, `observations`, `last_seen`, and `required_scopes`. Basis is
`configured`, `observed`, or `historical`; historical is reserved for incident
impact. Independent sources remain distinct assertions with distinct edge IDs.
For example, a Git call relationship and an OpenTelemetry call relationship are
both returned. The runtime does not average their confidence, invent confidence
from observation count, or replace configuration with telemetry.

Collectors should derive these assertions from Git, Argo CD, Kubernetes,
Terraform/Crossplane, provider inventory, service catalogs, SLO definitions,
telemetry, and incident records. This stage implements the normalized snapshot
boundary; connectors, discovery, ingestion schedules, durable graph storage, and
reconciliation of assertions across snapshots remain integration work.

## Query and traversal policy

Queries specify root, environment, mode, trusted `as_of` time, granted scopes,
minimum confidence and observed sample count, maximum relationship age, maximum
hops, and maximum nodes. The examples use confidence ≥0.8, at least 100 runtime
observations, and a five-minute age limit. Configuration assertions need no runtime
sample count. These thresholds are explicit example policy, not calibrated risk
probabilities. A live caller must not be allowed to grant its own scopes or lower
platform thresholds through model output.

`impact` follows reverse dependency and hosting edges, plus forward `DEPLOYS` and
`MANAGES` edges. `dependencies` reverses that traversal. Owners, SLOs, and incidents
are attached after traversal. A shared owner, SLO, or historical incident cannot
turn an unrelated service into an affected service. Repository deployment links
are also attached to reached services/workloads to expose their Git context.

Breadth-first traversal returns one deterministic shortest path per reached node.
All accepted edges between included nodes remain in the packet, so alternate
assertions and cycles are visible. Path steps state actual traversal direction;
the cited edge retains its original relationship direction and provenance.

Both node and edge access scopes must be granted before traversal. Unauthorized
nodes/edges are omitted entirely, including from filter diagnostics. Visible
relationships excluded for low confidence, sparse observations, staleness, or
future timestamps retain an exclusion reason. Historical incident edges may be
old; they still require sufficient confidence, authorized scopes, and a nonfuture
timestamp. This distinguishes history from current topology.

Queries permit at most ten hops and 500 nodes; snapshots permit 2,000 nodes and
10,000 edges. Annotations count toward the node limit. Cycles terminate and results
report `truncated: true` when bounds omit reachable context. `context_available`
exits 0, `bounded_context` exits 1, and invalid inputs exit 2. Neither successful
evaluation nor an empty neighborhood means infrastructure is safe to change.
Coverage is always `snapshot_only`; access filtering and unobserved relationships
can hide real dependencies even when traversal is not truncated.

## Graph-guided knowledge retrieval

`--documents` and `--question` together enable Stage 6 retrieval. The graph first
selects service catalog keys. Each service becomes a retrieval query with the same
environment, granted scopes, and review date. The existing retriever enforces
document access, authority, review metadata, and contradiction detection. The
output preserves per-service retrieval decisions, reviewed facts, and citations;
graph relevance cannot make an unauthorized document usable. An insufficient or
contradictory retrieval result stays visible and does not change graph coverage.
The CLI exit code describes topology truncation; consumers must inspect each
knowledge result before claiming an answer is grounded.

Graph, query, and packet fingerprints bind the output to exact inputs. They are
not signatures. Source names, confidence, observation counts, scopes, and clocks
in local files cannot authenticate themselves. Production adapters must supply
these independently of the model, authenticate caller identity, and authorize
access before delivering snapshots. Raw descriptive data and retrieved text are
untrusted; downstream renderers must escape text and models must not treat it as
instructions. `mutation_authorized` is always false.

This stage does not infer root cause, compute failure probabilities, simulate a
rollout, calculate a blast-radius risk score, or approve merges. A historical
`AFFECTED` link is evidence of prior impact, not proof that a new change will cause
the same failure. Live telemetry and model interpretation remain external, as does
mapping graph-derived relationships into Stage 12's trusted resource catalog.
Session 14's change-impact simulation is separate future work.

Continue with [local and Kubernetes deployment](14-local-and-kubernetes.md).
