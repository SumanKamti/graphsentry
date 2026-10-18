"""GraphSentry's FalkorDB access layer and synthetic demo graph.

All seed data is invented for this demo and uses RFC 5737 documentation IP ranges.
The graph is the source of truth for evidence, risk scoring, and action logging.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from falkordb import FalkorDB

from risk_engine import assess_risk

load_dotenv()

GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "graphsentry")


def connect_graph():
    """Return (client, graph) connected to FalkorDB using environment settings."""
    kwargs: dict[str, Any] = {
        "host": os.getenv("FALKORDB_HOST", "localhost"),
        "port": int(os.getenv("FALKORDB_PORT", "6379")),
    }
    password = os.getenv("FALKORDB_PASSWORD", "")
    if password:
        kwargs["password"] = password
    client = FalkorDB(**kwargs)
    graph = client.select_graph(GRAPH_NAME)
    # A tiny query verifies connectivity early and yields a useful error if offline.
    graph.query("RETURN 1 AS ok")
    return client, graph


def _q(value: Any) -> str:
    """Quote demo literals safely for Cypher seed statements."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return f"'{escaped}'"


# Each node uses a stable natural key so running the seed repeatedly is safe.
NODES = [
    ("Alert", "id", "AL-104", {"title": "Suspicious privileged login", "description": "A privileged account signed in from an untrusted source.", "event_time": "2026-10-18 08:12 UTC", "source": "Synthetic cloud audit log"}),
    ("Alert", "id", "AL-205", {"title": "Possible API token replay", "description": "A second account was accessed from the same suspicious source.", "event_time": "2026-10-18 08:19 UTC", "source": "Synthetic identity log"}),
    ("Alert", "id", "AL-309", {"title": "Unusual staging access", "description": "A read-only account accessed a non-production project.", "event_time": "2026-10-18 08:42 UTC", "source": "Synthetic cloud audit log"}),
    ("IP", "address", "203.0.113.77", {"reputation": "known-bad", "first_seen": "2026-10-18 08:12 UTC", "data_origin": "synthetic"}),
    ("IP", "address", "192.0.2.55", {"reputation": "clean", "first_seen": "2026-10-17 13:10 UTC", "data_origin": "synthetic"}),
    ("Account", "username", "maya.admin", {"privilege": "admin", "department": "Platform Engineering", "status": "active"}),
    ("Account", "username", "finance.ops", {"privilege": "standard", "department": "Finance", "status": "active"}),
    ("Account", "username", "ci-bot", {"privilege": "elevated", "department": "Engineering", "status": "active"}),
    ("Account", "username", "dev.reader", {"privilege": "read-only", "department": "Developer Experience", "status": "active"}),
    ("Device", "device_id", "LAPTOP-UNKNOWN-09", {"trust": "untrusted", "managed": False}),
    ("Device", "device_id", "FINANCE-WS-03", {"trust": "managed", "managed": True}),
    ("Device", "device_id", "BUILD-RUNNER-02", {"trust": "managed", "managed": True}),
    ("Device", "device_id", "DOCS-WS-11", {"trust": "managed", "managed": True}),
    ("Role", "name", "Platform Admin", {"risk_tier": "critical"}),
    ("Role", "name", "Billing Operator", {"risk_tier": "medium"}),
    ("Role", "name", "Build Automation", {"risk_tier": "high"}),
    ("Role", "name", "Read Only", {"risk_tier": "low"}),
    ("Project", "name", "payments-prod", {"environment": "production", "owner": "Platform Engineering"}),
    ("Project", "name", "billing-prod", {"environment": "production", "owner": "Finance Systems"}),
    ("Project", "name", "docs-staging", {"environment": "staging", "owner": "Developer Experience"}),
    ("Service", "name", "Payments API", {"criticality": "critical", "kind": "API"}),
    ("Service", "name", "Customer DB", {"criticality": "critical", "kind": "database"}),
    ("Service", "name", "Billing Worker", {"criticality": "high", "kind": "worker"}),
    ("Service", "name", "Docs Preview", {"criticality": "low", "kind": "web app"}),
    ("Indicator", "value", "SYNTH-BAD-IP-01", {"indicator_type": "ip-reputation", "confidence": "high", "description": "Synthetic indicator used for demo only"}),
]

# (from label, key, value, relationship, to label, key, value)
EDGES = [
    ("Alert", "id", "AL-104", "ORIGINATED_FROM", "IP", "address", "203.0.113.77"),
    ("Alert", "id", "AL-104", "TARGETS", "Account", "username", "maya.admin"),
    ("Alert", "id", "AL-104", "OBSERVED_ON", "Device", "device_id", "LAPTOP-UNKNOWN-09"),
    ("Alert", "id", "AL-104", "MATCHES_INDICATOR", "Indicator", "value", "SYNTH-BAD-IP-01"),
    ("Account", "username", "maya.admin", "USED_DEVICE", "Device", "device_id", "LAPTOP-UNKNOWN-09"),
    ("Account", "username", "maya.admin", "HAS_ROLE", "Role", "name", "Platform Admin"),
    ("Account", "username", "maya.admin", "CAN_ACCESS", "Project", "name", "payments-prod"),
    ("Project", "name", "payments-prod", "HOSTS", "Service", "name", "Payments API"),
    ("Service", "name", "Payments API", "DEPENDS_ON", "Service", "name", "Customer DB"),
    ("Service", "name", "Payments API", "DEPENDS_ON", "Service", "name", "Billing Worker"),
    ("IP", "address", "203.0.113.77", "SEEN_WITH", "Account", "username", "maya.admin"),
    ("IP", "address", "203.0.113.77", "SEEN_WITH", "Account", "username", "finance.ops"),
    ("IP", "address", "203.0.113.77", "SEEN_WITH", "Account", "username", "ci-bot"),
    ("Alert", "id", "AL-205", "ORIGINATED_FROM", "IP", "address", "203.0.113.77"),
    ("Alert", "id", "AL-205", "TARGETS", "Account", "username", "finance.ops"),
    ("Alert", "id", "AL-205", "OBSERVED_ON", "Device", "device_id", "FINANCE-WS-03"),
    ("Account", "username", "finance.ops", "USED_DEVICE", "Device", "device_id", "FINANCE-WS-03"),
    ("Account", "username", "finance.ops", "HAS_ROLE", "Role", "name", "Billing Operator"),
    ("Account", "username", "finance.ops", "CAN_ACCESS", "Project", "name", "billing-prod"),
    ("Project", "name", "billing-prod", "HOSTS", "Service", "name", "Billing Worker"),
    ("Account", "username", "ci-bot", "USED_DEVICE", "Device", "device_id", "BUILD-RUNNER-02"),
    ("Account", "username", "ci-bot", "HAS_ROLE", "Role", "name", "Build Automation"),
    ("Account", "username", "ci-bot", "CAN_ACCESS", "Project", "name", "payments-prod"),
    ("Alert", "id", "AL-309", "ORIGINATED_FROM", "IP", "address", "192.0.2.55"),
    ("Alert", "id", "AL-309", "TARGETS", "Account", "username", "dev.reader"),
    ("Alert", "id", "AL-309", "OBSERVED_ON", "Device", "device_id", "DOCS-WS-11"),
    ("IP", "address", "192.0.2.55", "SEEN_WITH", "Account", "username", "dev.reader"),
    ("Account", "username", "dev.reader", "USED_DEVICE", "Device", "device_id", "DOCS-WS-11"),
    ("Account", "username", "dev.reader", "HAS_ROLE", "Role", "name", "Read Only"),
    ("Account", "username", "dev.reader", "CAN_ACCESS", "Project", "name", "docs-staging"),
    ("Project", "name", "docs-staging", "HOSTS", "Service", "name", "Docs Preview"),
]


def seed_demo_graph(graph) -> dict[str, int]:
    """Upsert the synthetic graph and return counts for the UI."""
    node_count = 0
    edge_count = 0
    for label, key, value, props in NODES:
        prop_text = ", ".join(f"{k}: {_q(v)}" for k, v in props.items())
        set_clause = f" SET n += {{{prop_text}}}" if prop_text else ""
        query = f"MERGE (n:{label} {{{key}: {_q(value)}}}){set_clause}"
        graph.query(query)
        node_count += 1
    for from_label, from_key, from_value, rel, to_label, to_key, to_value in EDGES:
        query = (
            f"MATCH (a:{from_label} {{{from_key}: {_q(from_value)}}}), "
            f"(b:{to_label} {{{to_key}: {_q(to_value)}}}) "
            f"MERGE (a)-[:{rel}]->(b)"
        )
        graph.query(query)
        edge_count += 1
    return {"seed_nodes": node_count, "seed_relationships": edge_count}


def list_alerts(graph) -> list[dict[str, Any]]:
    rows = graph.query(
        "MATCH (a:Alert) RETURN a.id AS id, a.title AS title, "
        "a.description AS description, a.event_time AS event_time "
        "ORDER BY a.id"
    ).result_set
    return [dict(zip(["id", "title", "description", "event_time"], row)) for row in rows]


def investigate_alert(graph, alert_id: str) -> dict[str, Any]:
    """Read multi-hop evidence from FalkorDB. The graph drives scoring and context."""
    primary_query = """
    MATCH (a:Alert {id: $alert_id})-[:ORIGINATED_FROM]->(ip:IP)
    MATCH (a)-[:TARGETS]->(u:Account)
    OPTIONAL MATCH (u)-[:USED_DEVICE]->(d:Device)
    OPTIONAL MATCH (u)-[:HAS_ROLE]->(r:Role)
    RETURN a.id AS alert_id, a.title AS title, a.description AS description,
           a.event_time AS event_time, ip.address AS source_ip,
           ip.reputation AS reputation, u.username AS username,
           u.privilege AS privilege, u.department AS department,
           d.device_id AS device_id, d.trust AS device_trust,
           collect(DISTINCT r.name) AS roles
    """
    rows = graph.query(primary_query, params={"alert_id": alert_id}).result_set
    if not rows:
        raise ValueError(f"Alert {alert_id} was not found in FalkorDB. Seed the graph first.")
    row = rows[0]
    primary = dict(zip([
        "alert_id", "title", "description", "event_time", "source_ip", "reputation",
        "username", "privilege", "department", "device_id", "device_trust", "roles"
    ], row))

    shared_rows = graph.query("""
        MATCH (a:Alert {id: $alert_id})-[:ORIGINATED_FROM]->(ip:IP)-[:SEEN_WITH]->(other:Account)
        RETURN collect(DISTINCT other.username) AS accounts,
               count(DISTINCT other.username) AS account_count
    """, params={"alert_id": alert_id}).result_set
    shared = {"accounts": [], "account_count": 0}
    if shared_rows:
        shared = dict(zip(["accounts", "account_count"], shared_rows[0]))
    shared["accounts"] = shared.get("accounts") or []
    shared["account_count"] = int(shared.get("account_count") or 0)

    service_rows = graph.query("""
        MATCH (a:Alert {id: $alert_id})-[:TARGETS]->(u:Account)-[:CAN_ACCESS]->(p:Project)-[:HOSTS]->(s:Service)
        RETURN DISTINCT p.name AS project, p.environment AS environment,
               s.name AS service, s.criticality AS criticality
        ORDER BY project, service
    """, params={"alert_id": alert_id}).result_set
    services = [dict(zip(["project", "environment", "service", "criticality"], r)) for r in service_rows]

    dependency_rows = graph.query("""
        MATCH (a:Alert {id: $alert_id})-[:TARGETS]->(u:Account)-[:CAN_ACCESS]->(p:Project)-[:HOSTS]->(s:Service)
        MATCH (s)-[:DEPENDS_ON*1..3]->(d:Service)
        RETURN DISTINCT s.name AS parent_service, d.name AS dependency,
               d.criticality AS criticality
        ORDER BY parent_service, dependency
    """, params={"alert_id": alert_id}).result_set
    dependencies = [dict(zip(["parent_service", "dependency", "criticality"], r)) for r in dependency_rows]

    indicator_rows = graph.query("""
        MATCH (a:Alert {id: $alert_id})-[r:MATCHES_INDICATOR|OBSERVED_ON]->(i:Indicator)
        RETURN DISTINCT i.value AS value,
               i.indicator_type AS indicator_type,
               type(r) AS relationship,
               i.confidence AS confidence,
               i.severity AS severity,
               i.description AS description
        ORDER BY value
    """, params={"alert_id": alert_id}).result_set
    indicators = [
        dict(zip(["value", "indicator_type", "relationship", "confidence", "severity", "description"], r))
        for r in indicator_rows
    ]

    # Evidence-first scoring; no score is based on an LLM guess.
    assessment = assess_risk(primary, shared["account_count"], shared["accounts"], services, dependencies, indicators)

    return {
        "primary": primary,
        "indicators": indicators,
        "shared_accounts": shared["accounts"],
        "shared_account_count": shared["account_count"],
        "services": services,
        "dependencies": dependencies,
        "evidence": assessment["evidence"],
        "score": assessment["score"],
        "risk": assessment["risk"],
        "action": assessment["action"],
        "critical_services": assessment["critical_services"],
    }


def record_response_action(graph, alert_id: str, username: str, rationale: str) -> dict[str, Any]:
    """Persist a simulated response/action node in FalkorDB for auditability."""
    import uuid
    action_id = "ACT-" + uuid.uuid4().hex[:8].upper()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result = graph.query("""
        MATCH (a:Alert {id: $alert_id})
        MATCH (u:Account {username: $username})
        CREATE (ra:ResponseAction {id: $action_id, kind: 'SIMULATED_CONTAINMENT',
               status: 'SIMULATED_APPROVED', target: $username, rationale: $rationale,
               created_at: $created_at})
        CREATE (a)-[:HAS_RESPONSE_ACTION]->(ra)
        CREATE (ra)-[:TARGETS_ACCOUNT]->(u)
        RETURN ra.id AS id, ra.status AS status, ra.kind AS kind,
               ra.target AS target, ra.created_at AS created_at
    """, params={
        "alert_id": alert_id,
        "username": username,
        "action_id": action_id,
        "rationale": rationale,
        "created_at": created_at,
    }).result_set
    if not result:
        raise RuntimeError("FalkorDB did not return the new response action.")
    return dict(zip(["id", "status", "kind", "target", "created_at"], result[0]))


def list_response_actions(graph) -> list[dict[str, Any]]:
    rows = graph.query("""
        MATCH (a:Alert)-[:HAS_RESPONSE_ACTION]->(ra:ResponseAction)
        RETURN ra.id AS id, a.id AS alert_id, ra.kind AS kind, ra.status AS status,
               ra.target AS target, ra.rationale AS rationale, ra.created_at AS created_at
        ORDER BY ra.created_at DESC
        LIMIT 20
    """).result_set
    return [dict(zip(["id", "alert_id", "kind", "status", "target", "rationale", "created_at"], r)) for r in rows]


def graph_inventory(graph) -> dict[str, int]:
    """Return node and relationship counts. Handles isolated nodes and empty graphs."""
    results = graph.query("""
        OPTIONAL MATCH (n)
        WITH count(n) AS nodes
        OPTIONAL MATCH ()-[r]->()
        RETURN nodes, count(r) AS relationships
    """).result_set
    if not results:
        return {"nodes": 0, "relationships": 0}
    return {"nodes": int(results[0][0]), "relationships": int(results[0][1])}
