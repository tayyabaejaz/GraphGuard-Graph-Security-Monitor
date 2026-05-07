from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import networkx as nx
import time
import uuid
import math
from collections import defaultdict

app = FastAPI(title="Graph Security Monitor", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory graph and alert store ───────────────────────────────────────────
G = nx.DiGraph()
alerts: List[Dict] = []
write_log: List[Dict] = []
edge_write_counts: Dict[str, int] = defaultdict(int)  # source node → edge count in window
subgraph_tracker: Dict[str, List[str]] = defaultdict(list)  # batch_id → nodes

# ─── Seed with realistic baseline graph ────────────────────────────────────────
def seed_graph():
    baseline_nodes = [
        ("user_001", {"type": "user", "trust": "high",   "label": "Alice (Admin)"}),
        ("user_002", {"type": "user", "trust": "medium", "label": "Bob (Support)"}),
        ("user_003", {"type": "user", "trust": "medium", "label": "Carol (Dev)"}),
        ("user_004", {"type": "user", "trust": "low",    "label": "Dave (Guest)"}),
        ("org_acme", {"type": "org",  "trust": "high",   "label": "Acme Corp"}),
        ("org_beta", {"type": "org",  "trust": "medium", "label": "Beta Inc"}),
        ("res_db",   {"type": "resource", "trust": "high", "label": "Prod Database"}),
        ("res_api",  {"type": "resource", "trust": "high", "label": "Admin API"}),
        ("ticket_01",{"type": "ticket",   "trust": "high", "label": "Ticket #001"}),
        ("ticket_02",{"type": "ticket",   "trust": "high", "label": "Ticket #002"}),
    ]
    baseline_edges = [
        ("user_001", "org_acme", {"rel": "member_of",    "ts": time.time() - 8640000}),
        ("user_002", "org_acme", {"rel": "member_of",    "ts": time.time() - 7200000}),
        ("user_003", "org_beta", {"rel": "member_of",    "ts": time.time() - 5000000}),
        ("user_001", "res_db",   {"rel": "has_access",   "ts": time.time() - 4000000}),
        ("user_001", "res_api",  {"rel": "has_access",   "ts": time.time() - 4000000}),
        ("user_002", "ticket_01",{"rel": "owns",         "ts": time.time() - 3000000}),
        ("user_003", "ticket_02",{"rel": "owns",         "ts": time.time() - 2000000}),
        ("ticket_01","res_api",  {"rel": "references",   "ts": time.time() - 1000000}),
    ]
    for node_id, attrs in baseline_nodes:
        G.add_node(node_id, **attrs)
    for src, dst, attrs in baseline_edges:
        G.add_edge(src, dst, **attrs)

seed_graph()

# ─── Models ────────────────────────────────────────────────────────────────────
class NodeWrite(BaseModel):
    node_id: str
    node_type: str
    trust: str = "medium"
    label: str
    batch_id: Optional[str] = None

class EdgeWrite(BaseModel):
    source: str
    target: str
    relationship: str
    timestamp: Optional[float] = None
    batch_id: Optional[str] = None

class BatchWrite(BaseModel):
    nodes: List[NodeWrite]
    edges: List[EdgeWrite]
    batch_id: Optional[str] = None

# ─── Detection Engine ──────────────────────────────────────────────────────────
SUSPICIOUS_CROSS_TRUST = {("low", "high"), ("low", "medium")}
SENSITIVE_RESOURCES = {"res_db", "res_api"}
VELOCITY_THRESHOLD = 5      # max new edges from one source in 60s window
CLUSTER_SIZE_THRESHOLD = 3  # min nodes in a batch to check for subgraph injection
CLUSTER_DENSITY_THRESHOLD = 0.6  # edge density threshold within batch

def detect_suspicious_edge(src: str, dst: str, rel: str) -> Optional[Dict]:
    """Detect forged / privilege-escalation edges."""
    src_data = G.nodes.get(src, {})
    dst_data = G.nodes.get(dst, {})
    src_trust = src_data.get("trust", "medium")
    dst_trust = dst_data.get("trust", "high")

    # Rule 1 — low-trust node gaining access to sensitive resource
    if dst in SENSITIVE_RESOURCES and src_trust == "low":
        return {
            "rule": "SUSPICIOUS_EDGE",
            "severity": "critical",
            "title": "Low-trust node linked to sensitive resource",
            "detail": f"Node '{src}' (trust={src_trust}) attempting '{rel}' → '{dst}'. "
                      f"Low-trust entities should not connect to sensitive resources.",
            "nodes": [src, dst],
        }

    # Rule 2 — cross-trust relationship jump (low → high trust org)
    if (src_trust, dst_trust) in SUSPICIOUS_CROSS_TRUST and dst_data.get("type") == "org":
        return {
            "rule": "TRUST_ESCALATION",
            "severity": "high",
            "title": "Suspicious trust-boundary crossing",
            "detail": f"Edge from '{src}' (trust={src_trust}) to '{dst}' (trust={dst_trust}) "
                      f"crosses a trust boundary. Possible org-affiliation forgery.",
            "nodes": [src, dst],
        }

    # Rule 3 — edge velocity (too many edges from same source in short window)
    recent = [e for e in write_log
              if e.get("source") == src and time.time() - e.get("ts", 0) < 60]
    if len(recent) >= VELOCITY_THRESHOLD:
        return {
            "rule": "EDGE_VELOCITY",
            "severity": "high",
            "title": "High-velocity edge writes from single node",
            "detail": f"Node '{src}' has written {len(recent)+1} edges in the last 60 seconds. "
                      f"Threshold is {VELOCITY_THRESHOLD}. Possible relationship flooding.",
            "nodes": [src],
        }

    return None

def detect_subgraph_injection(batch_id: str, node_ids: List[str], edge_pairs: List[tuple]) -> Optional[Dict]:
    """Detect injected fake clusters — dense internal connectivity with few external ties."""
    if len(node_ids) < CLUSTER_SIZE_THRESHOLD:
        return None

    node_set = set(node_ids)
    internal_edges = [(s, t) for s, t in edge_pairs if s in node_set and t in node_set]
    external_edges = [(s, t) for s, t in edge_pairs if (s in node_set) != (t in node_set)]

    n = len(node_ids)
    max_possible = n * (n - 1)
    density = len(internal_edges) / max_possible if max_possible > 0 else 0

    new_nodes = [nid for nid in node_ids if nid not in G.nodes]
    new_node_ratio = len(new_nodes) / n if n > 0 else 0

    if density >= CLUSTER_DENSITY_THRESHOLD and new_node_ratio >= 0.5 and len(external_edges) <= 2:
        return {
            "rule": "SUBGRAPH_INJECTION",
            "severity": "critical",
            "title": "Probable subgraph injection detected",
            "detail": f"Batch '{batch_id}' introduced {n} nodes ({len(new_nodes)} new) "
                      f"with internal density {density:.0%} and only {len(external_edges)} "
                      f"external connections. Pattern matches fabricated cluster injection.",
            "nodes": node_ids,
        }
    return None

def make_alert(detection: Dict, context: Dict = {}) -> Dict:
    alert = {
        "id": str(uuid.uuid4())[:8],
        "ts": time.time(),
        "ts_human": time.strftime("%H:%M:%S"),
        **detection,
        **context,
    }
    alerts.insert(0, alert)
    return alert

# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/graph")
def get_graph():
    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes]
    edges = [{"source": u, "target": v, **G.edges[u, v]} for u, v in G.edges]
    return {"nodes": nodes, "edges": edges}

@app.post("/write/edge")
def write_edge(e: EdgeWrite):
    ts = e.timestamp or time.time()

    # Ensure nodes exist (auto-create unknowns as low-trust)
    for nid in [e.source, e.target]:
        if nid not in G.nodes:
            G.add_node(nid, type="unknown", trust="low", label=nid)

    alert = None
    detection = detect_suspicious_edge(e.source, e.target, e.relationship)
    if detection:
        alert = make_alert(detection, {"edge": {"source": e.source, "target": e.target, "rel": e.relationship}})

    G.add_edge(e.source, e.target, rel=e.relationship, ts=ts)
    write_log.append({"source": e.source, "target": e.target, "rel": e.relationship, "ts": ts})

    return {"status": "written", "alert": alert}

@app.post("/write/batch")
def write_batch(batch: BatchWrite):
    batch_id = batch.batch_id or str(uuid.uuid4())[:8]
    node_ids = [n.node_id for n in batch.nodes]
    edge_pairs = [(e.source, e.target) for e in batch.edges]
    fired_alerts = []

    # Write nodes
    for n in batch.nodes:
        G.add_node(n.node_id, type=n.node_type, trust=n.trust, label=n.label)

    # Write edges with per-edge checks
    for e in batch.edges:
        for nid in [e.source, e.target]:
            if nid not in G.nodes:
                G.add_node(nid, type="unknown", trust="low", label=nid)
        detection = detect_suspicious_edge(e.source, e.target, e.relationship)
        if detection:
            fired_alerts.append(make_alert(detection, {"batch_id": batch_id}))
        G.add_edge(e.source, e.target, rel=e.relationship, ts=e.timestamp or time.time())
        write_log.append({"source": e.source, "target": e.target, "ts": time.time()})

    # Subgraph injection check on whole batch
    subgraph_det = detect_subgraph_injection(batch_id, node_ids, edge_pairs)
    if subgraph_det:
        fired_alerts.append(make_alert(subgraph_det, {"batch_id": batch_id}))

    return {"status": "written", "batch_id": batch_id, "alerts": fired_alerts}

@app.get("/alerts")
def get_alerts(limit: int = 50):
    return {"alerts": alerts[:limit], "total": len(alerts)}

@app.get("/alerts/clear")
def clear_alerts():
    alerts.clear()
    return {"status": "cleared"}

@app.get("/stats")
def get_stats():
    critical = sum(1 for a in alerts if a.get("severity") == "critical")
    high     = sum(1 for a in alerts if a.get("severity") == "high")
    rules    = defaultdict(int)
    for a in alerts:
        rules[a.get("rule", "UNKNOWN")] += 1
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "total_alerts": len(alerts),
        "critical": critical,
        "high": high,
        "rules": dict(rules),
    }

@app.post("/simulate/{attack_type}")
def simulate_attack(attack_type: str):
    """Simulate known attack patterns for demo purposes."""
    if attack_type == "forged_edge":
        # Low-trust guest trying to access prod DB
        e = EdgeWrite(source="user_004", target="res_db", relationship="has_access")
        return write_edge(e)

    elif attack_type == "trust_escalation":
        # Low-trust guest suddenly affiliated with high-trust org
        e = EdgeWrite(source="user_004", target="org_acme", relationship="member_of")
        return write_edge(e)

    elif attack_type == "velocity_flood":
        # Rapid-fire edges from same source
        results = []
        targets = ["ticket_01", "ticket_02", "res_api", "org_acme", "org_beta", "res_db"]
        for t in targets:
            e = EdgeWrite(source="user_004", target=t, relationship="references")
            results.append(write_edge(e))
        return {"simulated": "velocity_flood", "writes": len(results)}

    elif attack_type == "subgraph_injection":
        # Inject a dense fake cluster with minimal external ties
        batch = BatchWrite(
            batch_id="inject_" + str(uuid.uuid4())[:4],
            nodes=[
                NodeWrite(node_id="ghost_01", node_type="user",     trust="low",  label="Ghost User 1"),
                NodeWrite(node_id="ghost_02", node_type="user",     trust="low",  label="Ghost User 2"),
                NodeWrite(node_id="ghost_03", node_type="org",      trust="low",  label="Ghost Org"),
                NodeWrite(node_id="ghost_04", node_type="resource", trust="low",  label="Ghost Resource"),
            ],
            edges=[
                EdgeWrite(source="ghost_01", target="ghost_02", relationship="ally"),
                EdgeWrite(source="ghost_01", target="ghost_03", relationship="member_of"),
                EdgeWrite(source="ghost_02", target="ghost_03", relationship="member_of"),
                EdgeWrite(source="ghost_03", target="ghost_04", relationship="owns"),
                EdgeWrite(source="ghost_02", target="ghost_04", relationship="has_access"),
                EdgeWrite(source="ghost_01", target="ghost_04", relationship="has_access"),
                # One thin external tie to sneak in
                EdgeWrite(source="ghost_03", target="org_acme",  relationship="partner"),
            ],
        )
        return write_batch(batch)

    raise HTTPException(status_code=400, detail=f"Unknown attack type: {attack_type}")

@app.get("/reset")
def reset_graph():
    G.clear()
    alerts.clear()
    write_log.clear()
    edge_write_counts.clear()
    seed_graph()
    return {"status": "reset"}