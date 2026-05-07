# GraphGuard: Graph Security Monitor

A real-time security monitoring system that detects **data poisoning** and **graph adversarial attacks** on context graphs. Built with FastAPI + D3.js.

---

## What It Does

Monitors a live context graph for:

| Detection Rule | Severity | Description |
|---|---|---|
| `SUSPICIOUS_EDGE` | 🔴 Critical | Low-trust node linked to a sensitive resource |
| `TRUST_ESCALATION` | 🟠 High | Edge crosses a trust boundary (low → high trust org) |
| `EDGE_VELOCITY` | 🟠 High | Too many edges from one source in 60s (flooding) |
| `SUBGRAPH_INJECTION` | 🔴 Critical | Dense cluster of mostly-new nodes with few external ties |

---

## Project Structure

```
graph-security-monitor/
├── backend/
│   └── main.py          # FastAPI app — graph store, detection engine, API
├── frontend/
│   └── index.html       # Dashboard — D3 graph viz + live alert feed
└── README.md
```

---

## Setup & Run

### 1. Install dependencies

```bash
pip install fastapi uvicorn networkx python-multipart
```

### 2. Start the backend

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open the dashboard

Open `frontend/index.html` directly in your browser.

---

## API Reference

### Read

| Endpoint | Method | Description |
|---|---|---|
| `/graph` | GET | Full graph (nodes + edges) |
| `/alerts` | GET | All fired alerts |
| `/stats` | GET | Node/edge/alert counts |

### Write

| Endpoint | Method | Body | Description |
|---|---|---|---|
| `/write/edge` | POST | `EdgeWrite` | Write a single edge |
| `/write/batch` | POST | `BatchWrite` | Write a batch (triggers subgraph check) |

### Simulate Attacks

| Endpoint | Method | Description |
|---|---|---|
| `/simulate/forged_edge` | POST | Low-trust user → sensitive resource |
| `/simulate/trust_escalation` | POST | Low-trust user → high-trust org |
| `/simulate/velocity_flood` | POST | Rapid-fire edges from same source |
| `/simulate/subgraph_injection` | POST | Inject a dense fake cluster |

### Utility

| Endpoint | Method | Description |
|---|---|---|
| `/reset` | GET | Reset graph to baseline + clear alerts |

---

## Example: Manual Edge Write

```bash
curl -X POST http://localhost:8000/write/edge \
  -H "Content-Type: application/json" \
  -d '{"source": "user_004", "target": "res_db", "relationship": "has_access"}'
```

---

## Example: Batch Write (Subgraph Injection Test)

```bash
curl -X POST http://localhost:8000/write/batch \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "test_batch",
    "nodes": [
      {"node_id": "n1", "node_type": "user", "trust": "low", "label": "Ghost 1"},
      {"node_id": "n2", "node_type": "user", "trust": "low", "label": "Ghost 2"},
      {"node_id": "n3", "node_type": "org",  "trust": "low", "label": "Ghost Org"}
    ],
    "edges": [
      {"source": "n1", "target": "n2", "relationship": "ally"},
      {"source": "n1", "target": "n3", "relationship": "member_of"},
      {"source": "n2", "target": "n3", "relationship": "member_of"}
    ]
  }'
```

---

## Extending the System

- **Add new detection rules** → extend `detect_suspicious_edge()` or add new detector functions in `main.py`
- **Persist the graph** → swap the in-memory `nx.DiGraph()` for Neo4j or NetworkX with file serialization
- **Add provenance tracking** → extend `NodeWrite` / `EdgeWrite` models with `source_system` and `confidence` fields
- **Webhook alerts** → add a webhook URL config and POST alerts to Slack/PagerDuty on critical detections

---

## Related Articles

- [Context Graphs: The Missing Layer Between AI and Understanding](https://medium.com/@tayyaba.ejaz25/when-the-map-becomes-the-target-data-poisoning-and-graph-adversarial-attacks-94b6c1962781)
- [When the Map Becomes the Target: Data Poisoning and Graph Adversarial Attacks](https://medium.com/@tayyaba.ejaz25/context-graphs-the-missing-layer-between-ai-and-real-understanding-96269c4ae824)