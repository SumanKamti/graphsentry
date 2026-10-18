from risk_engine import assess_risk
import sys
from unittest.mock import MagicMock

try:
    import falkordb
except ImportError:
    if "falkordb" not in sys.modules:
        sys.modules["falkordb"] = MagicMock()


def test_synthetic_high_impact_alert_scores_critical():
    primary = {
        "alert_id": "AL-104", "source_ip": "203.0.113.77", "reputation": "known-bad",
        "username": "maya.admin", "privilege": "admin", "device_id": "LAPTOP-UNKNOWN-09",
        "device_trust": "untrusted",
    }
    services = [{"service": "Payments API", "criticality": "critical"}]
    dependencies = [{"parent_service": "Payments API", "dependency": "Customer DB", "criticality": "critical"}]
    result = assess_risk(primary, 3, ["maya.admin", "finance.ops", "ci-bot"], services, dependencies)
    assert result["score"] == 100
    assert result["risk"] == "CRITICAL"
    assert len(result["evidence"]) == 5
    assert "Customer DB" in result["critical_services"]


def test_clean_low_privilege_alert_scores_low():
    primary = {
        "alert_id": "AL-309", "source_ip": "192.0.2.55", "reputation": "clean",
        "username": "dev.reader", "privilege": "read-only", "device_id": "DOCS-WS-11",
        "device_trust": "managed",
    }
    services = [{"service": "Docs Preview", "criticality": "low"}]
    result = assess_risk(primary, 1, ["dev.reader"], services, [])
    assert result["score"] == 0
    assert result["risk"] == "LOW"
    assert result["evidence"] == []


def test_score_is_capped_at_100():
    primary = {
        "source_ip": "203.0.113.77", "reputation": "known-bad", "username": "root",
        "privilege": "elevated", "device_id": "unknown", "device_trust": "untrusted",
    }
    result = assess_risk(primary, 12, ["many"], [{"service": "X", "criticality": "critical"}], [])
    assert result["score"] == 100


def test_alert_with_matching_high_confidence_indicator_contributes_risk():
    primary = {
        "alert_id": "AL-TEST", "source_ip": "198.51.100.1", "reputation": "clean",
        "username": "test.user", "privilege": "standard", "device_id": "WS-01",
        "device_trust": "managed",
    }
    indicators = [
        {"value": "SYNTH-BAD-IP-01", "indicator_type": "ip-reputation", "confidence": "high"}
    ]
    result = assess_risk(primary, 1, ["test.user"], [], [], indicators=indicators)
    assert result["score"] == 15
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["title"] == "Alert matches high-confidence threat indicator"
    assert "SYNTH-BAD-IP-01" in result["evidence"][0]["detail"]


def test_alert_with_matching_severe_indicator_contributes_risk():
    primary = {
        "alert_id": "AL-TEST", "source_ip": "198.51.100.1", "reputation": "clean",
        "username": "test.user", "privilege": "standard", "device_id": "WS-01",
        "device_trust": "managed",
    }
    indicators = [
        {"value": "EXPLOIT-SIGNATURE-09", "indicator_type": "exploit", "severity": "critical"}
    ]
    result = assess_risk(primary, 1, ["test.user"], [], [], indicators=indicators)
    assert result["score"] == 15
    assert len(result["evidence"]) == 1
    assert "EXPLOIT-SIGNATURE-09" in result["evidence"][0]["detail"]


def test_alert_with_no_matching_indicators():
    primary = {
        "alert_id": "AL-TEST", "source_ip": "198.51.100.1", "reputation": "clean",
        "username": "test.user", "privilege": "standard", "device_id": "WS-01",
        "device_trust": "managed",
    }
    result_empty = assess_risk(primary, 1, ["test.user"], [], [], indicators=[])
    assert result_empty["score"] == 0
    assert result_empty["evidence"] == []

    result_none = assess_risk(primary, 1, ["test.user"], [], [], indicators=None)
    assert result_none["score"] == 0
    assert result_none["evidence"] == []


def test_benign_or_low_severity_indicator_does_not_contribute_risk():
    primary = {
        "alert_id": "AL-TEST", "source_ip": "198.51.100.1", "reputation": "clean",
        "username": "test.user", "privilege": "standard", "device_id": "WS-01",
        "device_trust": "managed",
    }
    benign_indicators = [
        {"value": "INTERNAL-SCANNER", "severity": "low", "confidence": "high"},
        {"value": "ALLOWLIST-PROXY", "severity": "benign", "confidence": "high"},
        {"value": "MONITOR-ONLY", "severity": "info", "confidence": "high"},
        {"value": "HEALTHCHECK-PROBE", "severity": "clean", "confidence": "high"},
    ]
    result = assess_risk(primary, 1, ["test.user"], [], [], indicators=benign_indicators)
    assert result["score"] == 0
    assert result["evidence"] == []


def test_missing_optional_indicator_properties_handled_safely():
    primary = {
        "alert_id": "AL-TEST", "source_ip": "198.51.100.1", "reputation": "clean",
        "username": "test.user", "privilege": "standard", "device_id": "WS-01",
        "device_trust": "managed",
    }
    sparse_indicators = [
        {"value": "SPARSE-01"},
        {},
        {"indicator_type": "unknown", "description": "missing value and severity/confidence"},
    ]
    result = assess_risk(primary, 1, ["test.user"], [], [], indicators=sparse_indicators)
    assert result["score"] == 0
    assert result["evidence"] == []


def test_full_investigation_scores_with_matching_indicator():
    primary = {
        "alert_id": "AL-104", "source_ip": "203.0.113.77", "reputation": "known-bad",
        "username": "maya.admin", "privilege": "admin", "device_id": "LAPTOP-UNKNOWN-09",
        "device_trust": "untrusted",
    }
    services = [{"service": "Payments API", "criticality": "critical"}]
    dependencies = [{"parent_service": "Payments API", "dependency": "Customer DB", "criticality": "critical"}]
    indicators = [
        {"value": "SYNTH-BAD-IP-01", "indicator_type": "ip-reputation", "confidence": "high"}
    ]
    result = assess_risk(primary, 3, ["maya.admin", "finance.ops", "ci-bot"], services, dependencies, indicators)
    assert result["score"] == 100
    assert result["risk"] == "CRITICAL"
    assert len(result["evidence"]) == 6  # 5 baseline rules + 1 indicator rule
    assert any(e["title"] == "Alert matches high-confidence threat indicator" for e in result["evidence"])


def test_investigate_alert_queries_indicators_via_mock():
    from unittest.mock import MagicMock
    from graph_service import investigate_alert

    mock_graph = MagicMock()

    # Configure query results for the 5 queries in order:
    # 1. primary_query
    primary_res = MagicMock()
    primary_res.result_set = [[
        "AL-104", "Suspicious privileged login", "Untrusted source",
        "2026-10-18 08:12 UTC", "203.0.113.77", "known-bad",
        "maya.admin", "admin", "Platform Engineering",
        "LAPTOP-UNKNOWN-09", "untrusted", ["Platform Admin"]
    ]]
    # 2. shared_rows
    shared_res = MagicMock()
    shared_res.result_set = [[["maya.admin", "finance.ops", "ci-bot"], 3]]
    # 3. service_rows
    service_res = MagicMock()
    service_res.result_set = [["payments-prod", "production", "Payments API", "critical"]]
    # 4. dependency_rows
    dep_res = MagicMock()
    dep_res.result_set = [["Payments API", "Customer DB", "critical"]]
    # 5. indicator_rows
    ind_res = MagicMock()
    ind_res.result_set = [[
        "SYNTH-BAD-IP-01", "ip-reputation", "MATCHES_INDICATOR", "high", None, "Synthetic indicator used for demo only"
    ]]

    mock_graph.query.side_effect = [primary_res, shared_res, service_res, dep_res, ind_res]

    inv = investigate_alert(mock_graph, "AL-104")

    assert mock_graph.query.call_count == 5
    # Verify indicator query was executed
    indicator_call = mock_graph.query.call_args_list[4]
    query_text = indicator_call[0][0]
    assert "MATCHES_INDICATOR" in query_text
    assert "OBSERVED_ON" in query_text
    assert indicator_call[1]["params"] == {"alert_id": "AL-104"}

    assert len(inv["indicators"]) == 1
    assert inv["indicators"][0]["value"] == "SYNTH-BAD-IP-01"
    assert inv["indicators"][0]["relationship"] == "MATCHES_INDICATOR"
    assert inv["score"] == 100
    assert inv["risk"] == "CRITICAL"
    assert len(inv["evidence"]) == 6


def test_investigate_alert_with_multiple_indicators_mock():
    from unittest.mock import MagicMock
    from graph_service import investigate_alert

    mock_graph = MagicMock()
    primary_res = MagicMock(result_set=[[
        "AL-200", "Token Abuse", "Suspicious token",
        "2026-10-18 09:00 UTC", "198.51.100.2", "clean",
        "test.user", "standard", "IT",
        "WS-99", "managed", []
    ]])
    shared_res = MagicMock(result_set=[[["test.user"], 1]])
    service_res = MagicMock(result_set=[])
    dep_res = MagicMock(result_set=[])
    ind_res = MagicMock(result_set=[
        ["IND-C2-01", "c2-domain", "MATCHES_INDICATOR", "high", "critical", "Known C2"],
        ["IND-HASH-02", "file-hash", "OBSERVED_ON", "critical", "high", "Known Malware Hash"]
    ])
    mock_graph.query.side_effect = [primary_res, shared_res, service_res, dep_res, ind_res]

    inv = investigate_alert(mock_graph, "AL-200")
    assert len(inv["indicators"]) == 2
    assert inv["indicators"][0]["value"] == "IND-C2-01"
    assert inv["indicators"][1]["value"] == "IND-HASH-02"
    assert inv["indicators"][1]["relationship"] == "OBSERVED_ON"
    assert inv["score"] == 15
    assert any("2 verified threat indicator(s)" in e["detail"] for e in inv["evidence"])


def test_isolated_node_alert_without_connected_assets():
    """An alert targeting an account with no projects, services, or shared accounts."""
    primary = {
        "alert_id": "AL-ISOLATED", "source_ip": "192.0.2.100", "reputation": "clean",
        "username": "isolated.serviceacct", "privilege": "read-only",
        "device_id": None, "device_trust": "managed",
    }
    # Completely isolated: no shared accounts, no services, no dependencies, no indicators
    result = assess_risk(primary, 0, [], [], [], indicators=[])
    assert result["score"] == 0
    assert result["risk"] == "LOW"
    assert result["evidence"] == []

    # Isolated node with only a threat indicator attached
    result_with_ind = assess_risk(
        primary, 0, [], [], [],
        indicators=[{"value": "IND-SOLO", "confidence": "high", "severity": "high"}]
    )
    assert result_with_ind["score"] == 15
    assert len(result_with_ind["evidence"]) == 1
    assert "IND-SOLO" in result_with_ind["evidence"][0]["detail"]


def test_graph_inventory_empty_graph():
    from unittest.mock import MagicMock
    from graph_service import graph_inventory

    mock_graph = MagicMock()
    # When empty, OPTIONAL MATCH returns 1 row with [[0, 0]]
    mock_graph.query.return_value = MagicMock(result_set=[[0, 0]])

    counts = graph_inventory(mock_graph)
    assert counts == {"nodes": 0, "relationships": 0}

    # When query returns empty list
    mock_graph.query.return_value = MagicMock(result_set=[])
    counts_empty = graph_inventory(mock_graph)
    assert counts_empty == {"nodes": 0, "relationships": 0}


def test_graph_inventory_nodes_and_relationships():
    from unittest.mock import MagicMock
    from graph_service import graph_inventory

    mock_graph = MagicMock()
    mock_graph.query.return_value = MagicMock(result_set=[[25, 31]])

    counts = graph_inventory(mock_graph)
    assert counts == {"nodes": 25, "relationships": 31}


def test_graph_inventory_isolated_nodes_no_relationships():
    """Validates the fix: graphs with isolated nodes and 0 relationships return correct node count."""
    from unittest.mock import MagicMock
    from graph_service import graph_inventory

    mock_graph = MagicMock()
    # 7 isolated nodes, 0 relationships
    mock_graph.query.return_value = MagicMock(result_set=[[7, 0]])

    counts = graph_inventory(mock_graph)
    assert counts == {"nodes": 7, "relationships": 0}

    # Verify query text uses OPTIONAL MATCH
    query_executed = mock_graph.query.call_args[0][0]
    assert "OPTIONAL MATCH (n)" in query_executed
    assert "OPTIONAL MATCH ()-[r]->()" in query_executed


def _is_falkordb_running() -> bool:
    try:
        from falkordb import FalkorDB
        # Ensure FalkorDB is a real class, not a MagicMock
        if hasattr(FalkorDB, "_mock_return_value") or "MagicMock" in type(FalkorDB).__name__:
            return False
        from graph_service import connect_graph
        client, graph = connect_graph()
        return True
    except Exception:
        return False


def test_live_falkordb_indicator_cypher_query():
    """Integration test executed against live FalkorDB using an isolated temporary graph."""
    import pytest
    if not _is_falkordb_running():
        pytest.skip("FalkorDB is offline or falkordb package is not installed in the test runner")

    import uuid
    from graph_service import connect_graph, investigate_alert

    test_graph_name = f"test_graphsentry_{uuid.uuid4().hex[:8]}"
    client, _ = connect_graph(test_graph_name)
    test_graph = client.select_graph(test_graph_name)

    try:
        # Seed minimal synthetic nodes and relationships matching existing schema
        test_graph.query("""
            MERGE (a1:Alert {id: 'AL-104', title: 'Suspicious privileged login', description: 'Untrusted source', event_time: '2026-10-18 08:12 UTC', source: 'Synthetic audit log'})
            MERGE (ip1:IP {address: '203.0.113.77', reputation: 'known-bad', first_seen: '2026-10-18 08:12 UTC', data_origin: 'synthetic'})
            MERGE (u1:Account {username: 'maya.admin', privilege: 'admin', department: 'Platform Engineering', status: 'active'})
            MERGE (d1:Device {device_id: 'LAPTOP-UNKNOWN-09', trust: 'untrusted', managed: false})
            MERGE (r1:Role {name: 'Platform Admin', risk_tier: 'critical'})
            MERGE (p1:Project {name: 'payments-prod', environment: 'production', owner: 'Platform Engineering'})
            MERGE (s1:Service {name: 'Payments API', criticality: 'critical', kind: 'API'})
            MERGE (db1:Service {name: 'Customer DB', criticality: 'critical', kind: 'database'})
            MERGE (ind:Indicator {value: 'SYNTH-BAD-IP-01', indicator_type: 'ip-reputation', confidence: 'high', description: 'Synthetic indicator used for demo only'})

            MERGE (a1)-[:ORIGINATED_FROM]->(ip1)
            MERGE (a1)-[:TARGETS]->(u1)
            MERGE (a1)-[:OBSERVED_ON]->(d1)
            MERGE (a1)-[:MATCHES_INDICATOR]->(ind)
            MERGE (u1)-[:USED_DEVICE]->(d1)
            MERGE (u1)-[:HAS_ROLE]->(r1)
            MERGE (u1)-[:CAN_ACCESS]->(p1)
            MERGE (p1)-[:HOSTS]->(s1)
            MERGE (s1)-[:DEPENDS_ON]->(db1)
            MERGE (ip1)-[:SEEN_WITH]->(u1)

            MERGE (a2:Alert {id: 'AL-205', title: 'Token abuse', description: 'Replay', event_time: '2026-10-18 08:19 UTC', source: 'Synthetic identity log'})
            MERGE (u2:Account {username: 'finance.ops', privilege: 'standard', department: 'Finance', status: 'active'})
            MERGE (u3:Account {username: 'ci-bot', privilege: 'elevated', department: 'Engineering', status: 'active'})
            MERGE (a2)-[:ORIGINATED_FROM]->(ip1)
            MERGE (a2)-[:TARGETS]->(u2)
            MERGE (ip1)-[:SEEN_WITH]->(u2)
            MERGE (ip1)-[:SEEN_WITH]->(u3)
        """)

        # 1. Investigate AL-104 (has matching indicator)
        inv_104 = investigate_alert(test_graph, "AL-104")
        assert len(inv_104["indicators"]) == 1
        ind = inv_104["indicators"][0]
        assert ind["value"] == "SYNTH-BAD-IP-01"
        assert ind["indicator_type"] == "ip-reputation"
        assert ind["relationship"] == "MATCHES_INDICATOR"
        assert ind["confidence"] == "high"
        assert ind["description"] == "Synthetic indicator used for demo only"
        assert inv_104["score"] == 100
        assert inv_104["risk"] == "CRITICAL"
        assert any(e["title"] == "Alert matches high-confidence threat indicator" for e in inv_104["evidence"])

        # 2. Investigate AL-205 (no matching indicators in graph)
        inv_205 = investigate_alert(test_graph, "AL-205")
        assert inv_205["indicators"] == []
        assert not any(e["title"] == "Alert matches high-confidence threat indicator" for e in inv_205["evidence"])

    finally:
        try:
            test_graph.delete()
        except Exception:
            pass


