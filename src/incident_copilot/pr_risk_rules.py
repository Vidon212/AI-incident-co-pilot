"""Deterministic operational invariants for explicitly supported normalized profiles."""


# The finding schema has five descriptive fields and an independent policy flag.
# pylint: disable-next=too-many-arguments
def _finding(code, severity, summary, measurements, recommendation, *, blocks=False):
    """Preserve measured deltas separately from interpretation and review suggestions."""
    return {"code": code, "severity": severity, "summary": summary,
            "measurements": measurements, "recommendation": recommendation, "blocks_merge": blocks}


def _hpa(resource, metrics, _context):
    """Do not reduce the ceiling below measured demand or silently alter the CPU signal."""
    before, after = resource["before"], resource["after"]
    findings = []
    if (after["max_replicas"] < before["max_replicas"]
            and (after["max_replicas"] < metrics["peak_replicas"]
                 or metrics["days_above_proposed_max"] > 0)):
        findings.append(_finding("HPA_BELOW_DEMAND", "high",
            "The proposed scaling ceiling is below observed production demand.",
            {"old_max": before["max_replicas"], "new_max": after["max_replicas"], **metrics},
            "Keep capacity above measured demand or provide reviewed evidence of changed traffic "
            "or per-pod capacity before reducing the ceiling.", blocks=True))
    if after["cpu_target_percent"] != before["cpu_target_percent"] or not metrics["cpu_signal"]:
        findings.append(_finding("HPA_SIGNAL_REVIEW", "medium",
            "The CPU target changed or CPU is not the verified scaling signal.",
            {"before_cpu_target": before["cpu_target_percent"],
             "after_cpu_target": after["cpu_target_percent"]},
            "Review the effective HPA metrics and scaling response with the service owner."))
    return findings


def _database(resource, metrics, _context):
    """Capacity changes need memory headroom and a separately reviewed CPU projection."""
    before, after = resource["before"], resource["after"]
    findings = []
    if after["memory_gib"] < metrics["memory_p95_gib"]:
        findings.append(_finding("DB_MEMORY_BELOW_P95", "critical",
            "Proposed database memory is below measured p95 memory demand.",
            {"new_memory_gib": after["memory_gib"], **metrics},
            "Retain memory above demand and review dependent services and prior incidents.",
            blocks=True))
    estimate = metrics["cpu_peak_fraction"] * before["cpu_cores"] / after["cpu_cores"]
    if after["cpu_cores"] < before["cpu_cores"]:
        findings.append(_finding("DB_CPU_DOWNSIZE", "high" if estimate >= .9 else "medium",
            "Reducing CPU changes headroom; linear utilization is only a screening estimate.",
            {"old_cores": before["cpu_cores"], "new_cores": after["cpu_cores"],
             "estimated_peak_fraction": estimate, "observed_peak_fraction":
             metrics["cpu_peak_fraction"]},
            "Validate workload behavior and provider tier with capacity tests before downsizing."))
    return findings


def _storage(resource, metrics, context):
    """A validated recurring capacity invariant becomes ordinary deterministic policy."""
    before, after = resource["before"]["storage_gib"], resource["after"]["storage_gib"]
    minimum = metrics["used_gib"] + max(context["storage_safety_margin_gib"],
                                        metrics["growth_30d_gib"])
    if after < minimum:
        return [_finding("STORAGE_BELOW_SAFE_FLOOR", "critical",
            "Requested storage is below usage plus the required growth/safety reserve.",
            {"requested_gib": after, "required_gib": minimum, **metrics,
             "safety_margin_gib": context["storage_safety_margin_gib"]},
            "Keep storage above the safe floor; review provider resize and recovery.", blocks=True)]
    if after < before:
        return [_finding("STORAGE_SHRINK_REVIEW", "high",
            "Storage shrink needs provider and migration review even above the capacity floor.",
            {"before_gib": before, "after_gib": after, "required_gib": minimum},
            "Confirm provider support for shrinking and review a migration/recovery plan.")]
    return []


def _network(resource, metrics, _context):
    """Calculate selector set differences; equal-sized replacements can still widen access."""
    namespaces = {item["name"]: item for item in metrics["namespaces"]}

    def selected(spec):
        selector = spec["ingress_namespace_selector"]
        return {name for name, item in namespaces.items()
                if all(item["labels"].get(key) == value for key, value in selector.items())}

    before, after = selected(resource["before"]), selected(resource["after"])
    added, removed = after - before, before - after
    if added or removed:
        return [_finding("NETWORK_PEER_SET_CHANGED", "high",
            "Ingress peer namespace membership changed; review potential access and connectivity.",
            {"before_namespace_count": len(before), "after_namespace_count": len(after),
             "added_namespaces": sorted(added), "removed_namespaces": sorted(removed),
             "potentially_added_workloads": sum(namespaces[name]["workloads"] for name in added)},
            "Request security and service-owner review; inspect additive policies, ports, CNI "
            "enforcement, and caller egress before claiming effective reachability.")]
    return []


def _deployment(resource, metrics, _context):
    """Compare incremental CPU and node placement separately; PDBs do not gate rollouts."""
    before, after = resource["before"], resource["after"]
    old_cpu = before["replicas"] * before["cpu_request_cores"]
    new_cpu = after["replicas"] * after["cpu_request_cores"]
    incremental = max(0, new_cpu - old_cpu)
    findings = []
    if incremental > metrics["free_cpu_cores"]:
        findings.append(_finding("CPU_INCREMENT_EXCEEDS_FREE", "high",
            "Additional steady-state CPU requests exceed currently free cluster CPU.",
            {"old_total_cpu": old_cpu, "new_total_cpu": new_cpu,
             "incremental_cpu": incremental, "free_cpu": metrics["free_cpu_cores"],
             "node_autoscaler_at_max": metrics["node_autoscaler_at_max"]},
            "Validate node-pool expansion or stage resource changes before this rollout.",
            blocks=metrics["node_autoscaler_at_max"]))
    needs_pods = (after["cpu_request_cores"] != before["cpu_request_cores"]
                  or after["replicas"] > before["replicas"])
    if (needs_pods and after["max_unavailable"] == 0 and after["max_surge"] > 0
            and after["cpu_request_cores"] > metrics["largest_free_node_cpu_cores"]):
        findings.append(_finding("ROLLOUT_NO_INITIAL_CPU_PLACEMENT", "high",
            "No current node can fit a new pod while zero unavailability is required.",
            {"pod_cpu": after["cpu_request_cores"],
             "old_total_cpu": old_cpu, "new_total_cpu": new_cpu,
             "incremental_cpu": incremental, "free_cpu": metrics["free_cpu_cores"],
             "largest_free_node_cpu": metrics["largest_free_node_cpu_cores"],
             "max_surge": after["max_surge"], "max_unavailable": after["max_unavailable"]},
            "Review node capacity, placement constraints and Deployment strategy. PDBs do not "
            "directly constrain Deployment rolling updates.",
            blocks=metrics["node_autoscaler_at_max"]))
    if after["replicas"] - after["max_unavailable"] < metrics["pdb_min_available"]:
        findings.append(_finding("ROLLOUT_AVAILABILITY_REVIEW", "medium",
            "Deployment strategy permits fewer available replicas than the recorded PDB target.",
            {"strategy_min_available": after["replicas"] - after["max_unavailable"],
             "pdb_min_available": metrics["pdb_min_available"]},
            "Align rolling-update availability with the service SLO. A PDB governs voluntary "
            "evictions, not the Deployment controller's rolling-update deletion decisions."))
    return findings


RULES = {"HorizontalPodAutoscaler": _hpa, "CloudSQLInstance": _database,
         "PostgreSQLInstance": _storage, "NetworkPolicy": _network, "Deployment": _deployment}
