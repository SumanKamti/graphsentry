from __future__ import annotations

import html
import os

import streamlit as st
from dotenv import load_dotenv

from agent import make_brief
from graph_service import (
    connect_graph,
    graph_inventory,
    investigate_alert,
    list_alerts,
    list_response_actions,
    record_response_action,
    seed_demo_graph,
)

load_dotenv()
st.set_page_config(
    page_title="GraphSentry | Security Investigation Agent",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
.badge { display:inline-block; font-family:'DM Mono',monospace; font-size:11px; padding:3px 8px; border-radius:4px; border:1px solid; letter-spacing:0.5px; }
.badge-red { color:#ff8da0; background:#331721; border-color:#6e2d41; }
.badge-orange { color:#ffce91; background:#322617; border-color:#6b4d26; }
.badge-yellow { color:#f2e09a; background:#302e19; border-color:#625d2c; }
.badge-green { color:#87e3bd; background:#152d27; border-color:#2a6650; }
.badge-violet { color:#c4b5fd; background:#241c3a; border-color:#4c3a70; }
.panel { background:#10131c; border:1px solid #282d3b; border-radius:8px; padding:14px 16px; margin-bottom:12px; }
.panel-label { color:#8e83ff; font-family:'DM Mono',monospace; font-size:10px; letter-spacing:1px; text-transform:uppercase; margin-bottom:6px; }
.evidence { background:#0d1018; border:1px solid #282d3b; border-radius:8px; padding:12px 14px; margin:8px 0; }
.evidence-title { font-weight:600; font-size:13px; color:#eef0f8; }
.evidence-detail { color:#9ba3b5; font-size:12px; margin-top:3px; }
.evidence-points { color:#8e83ff; font-family:'DM Mono',monospace; font-size:11px; float:right; font-weight:500; }
.small-note { color:#9ba3b5; font-size:12px; line-height:1.5; }
div[data-testid="stMetricValue"] { font-size:24px; font-weight:700; }
.block-container { padding-top:2rem; padding-bottom:2rem; max-width:1400px; }
</style>
""", unsafe_allow_html=True)


def risk_badge(risk: str) -> str:
    cls = {"CRITICAL": "badge-red", "HIGH": "badge-orange", "MEDIUM": "badge-yellow", "LOW": "badge-green"}.get(risk, "badge-yellow")
    return f'<span class="badge {cls}">{html.escape(risk)}</span>'


def graphviz_for(inv: dict) -> str:
    """Build a visible graph diagram from records returned by FalkorDB queries."""
    p = inv["primary"]
    nodes: dict[str, tuple[str, str]] = {}
    edges: list[tuple[str, str, str]] = []

    def add_node(key: str, label: str, color: str = "#171a28"):
        nodes[key] = (label, color)

    def add_edge(source: str, target: str, label: str):
        edges.append((source, target, label))

    add_node("alert", f"ALERT\n{p['alert_id']}\n{p['title']}", "#33203b")
    add_node("ip", f"SOURCE IP\n{p['source_ip']}\n{p['reputation']}", "#40202d" if p['reputation'] in {"known-bad", "malicious"} else "#18302f")
    add_node("acct", f"ACCOUNT\n{p['username']}\n{p['privilege']}", "#33203b" if p['privilege'] in {"admin", "elevated"} else "#20283a")
    add_edge("alert", "ip", "ORIGINATED_FROM")
    add_edge("alert", "acct", "TARGETS")

    device = p.get("device_id")
    if device:
        add_node("device", f"DEVICE\n{device}\n{p.get('device_trust')}", "#40202d" if p.get("device_trust") == "untrusted" else "#18302f")
        add_edge("acct", "device", "USED_DEVICE")
    for idx, role in enumerate(p.get("roles") or []):
        rk = f"role{idx}"
        add_node(rk, f"ROLE\n{role}", "#29264a")
        add_edge("acct", rk, "HAS_ROLE")
    for idx, account in enumerate(inv["shared_accounts"]):
        if account == p["username"]:
            continue
        ak = f"shared{idx}"
        add_node(ak, f"RELATED ACCOUNT\n{account}", "#20283a")
        add_edge("ip", ak, "SEEN_WITH")
    for idx, service in enumerate(inv["services"]):
        pk, sk = f"project{idx}", f"service{idx}"
        add_node(pk, f"PROJECT\n{service['project']}\n{service['environment']}", "#1d2f3b")
        add_node(sk, f"SERVICE\n{service['service']}\n{service['criticality']}", "#23352f" if service['criticality'] in {"critical", "high"} else "#20283a")
        add_edge("acct", pk, "CAN_ACCESS")
        add_edge(pk, sk, "HOSTS")
    for idx, dep in enumerate(inv["dependencies"]):
        dk = f"dependency{idx}"
        add_node(dk, f"DEPENDENCY\n{dep['dependency']}\n{dep['criticality']}", "#23352f" if dep['criticality'] in {"critical", "high"} else "#20283a")
        # Link each dependency to the matching parent service if one is displayed.
        parent_idx = next((i for i, s in enumerate(inv["services"]) if s["service"] == dep["parent_service"]), None)
        if parent_idx is not None:
            add_edge(f"service{parent_idx}", dk, "DEPENDS_ON")
    for idx, ind in enumerate(inv.get("indicators") or []):
        ik = f"indicator{idx}"
        status_text = ind.get("severity") or ind.get("confidence") or ind.get("indicator_type") or "threat"
        add_node(ik, f"INDICATOR\n{ind['value']}\n{status_text}", "#40202d")
        rel = ind.get("relationship") or "MATCHES_INDICATOR"
        add_edge("alert", ik, rel)

    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines = [
        'digraph G {',
        'graph [bgcolor="#0b0e15", pad="0.25", rankdir=LR, nodesep="0.38", ranksep="0.55", splines=curved];',
        'node [shape=box, style="rounded,filled", color="#3b4055", fontcolor="#f0f1fb", fontname="Arial", fontsize=10, margin="0.15,0.10"];',
        'edge [color="#8179d8", fontcolor="#a8a3e7", fontname="Arial", fontsize=8, arrowsize=0.7];',
    ]
    for node_id, (label, fill) in nodes.items():
        lines.append(f'{node_id} [label="{esc(label)}", fillcolor="{fill}"];')
    for source, target, label in edges:
        lines.append(f'{source} -> {target} [label="{esc(label)}"];')
    lines.append('}')
    return "\n".join(lines)


# 1. Header
header_left, header_right = st.columns([3, 1])
with header_left:
    st.title("◈ GraphSentry")
    st.caption("Graph-first security triage and blast radius investigation agent")

# 2. Connection error state
try:
    client, graph = connect_graph()
except Exception as exc:
    with header_right:
        st.markdown("<div style='text-align:right;padding-top:1.5rem;'><span class='badge badge-red'>● FALKORDB OFFLINE</span></div>", unsafe_allow_html=True)
    st.error("Cannot connect to FalkorDB. Check that the database is running and reachable.")
    st.markdown("""
- **Local development:** Start the container with `docker compose up -d falkordb` and verify port 6379 is open.
- **Cloud deployment:** Verify your hosting environment variables: `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_PASSWORD`, and `FALKORDB_SSL=true` (or `FALKORDB_URL`).
    """)
    st.caption(f"Connection detail: {type(exc).__name__}: {exc}")
    st.stop()

with header_right:
    st.markdown("<div style='text-align:right;padding-top:1.5rem;'><span class='badge badge-green'>● FALKORDB CONNECTED</span></div>", unsafe_allow_html=True)

# 3. Sidebar
with st.sidebar:
    st.markdown("### ◈ GraphSentry")
    st.caption("GRAPH-POWERED SECURITY TRIAGE")
    st.divider()
    st.markdown("**Workspace**")
    st.markdown("<span class='badge badge-green'>FALKORDB CONNECTED</span>", unsafe_allow_html=True)
    _host_disp = os.getenv("FALKORDB_HOST", "localhost")
    _ssl_on = os.getenv("FALKORDB_SSL", os.getenv("FALKORDB_TLS", "")).strip().lower() in {"true", "1", "yes", "on"}
    _ssl_tag = " (TLS)" if _ssl_on else ""
    st.markdown(f"<span class='small-note'>Host: `{html.escape(_host_disp)}`{_ssl_tag}</span>", unsafe_allow_html=True)
    st.markdown(f"<span class='small-note'>Graph: `{html.escape(os.getenv('FALKORDB_GRAPH', 'graphsentry'))}`</span>", unsafe_allow_html=True)
    st.divider()
    st.markdown("**Investigation controls**")
    if st.button("↻ Seed / refresh demo context", use_container_width=True):
        try:
            counts = seed_demo_graph(graph)
            st.session_state["seed_counts"] = counts
            st.session_state.pop("investigation", None)
            st.success(f"Seeded {counts['seed_nodes']} node types/records and {counts['seed_relationships']} relationships.")
            st.rerun()
        except Exception as exc:
            st.error(f"Seed failed: {exc}")
    st.caption("Synthetic demo records only. No production systems are connected.")
    st.divider()
    with st.expander("ℹ️ About GraphSentry", expanded=False):
        st.markdown("""
**GraphSentry** connects security alerts to identities, permissions, projects, and services using multi-hop traversals in FalkorDB to calculate risk and map blast radius.

- **Synthetic data**: All alerts, IPs (RFC 5737 ranges), identities, and assets are synthetic demo records.
- **Simulated response**: Containment actions record audit nodes in FalkorDB; no real accounts or cloud resources are altered.
- **Optional Groq LLM**: Natural-language summaries use Groq when `GROQ_API_KEY` is provided, with deterministic fallback.
- **Limitations**: Hackathon prototype scoped to demonstrated attack patterns.
        """)

# 4. Auto-seed + alert loading
try:
    inventory = graph_inventory(graph)
    if inventory["nodes"] == 0:
        seed_demo_graph(graph)
        inventory = graph_inventory(graph)
    alerts = list_alerts(graph)
except Exception as exc:
    st.error(f"Could not load graph records: {type(exc).__name__}: {exc}")
    st.stop()

if not alerts:
    st.warning("No alerts exist yet. Use 'Seed / refresh demo context' in the sidebar.")
    st.stop()

# 5. Alert selection
st.divider()
left_select, right_status = st.columns([3, 1])
with left_select:
    options = {f"{a['id']}  ·  {a['title']}": a["id"] for a in alerts}
    labels = list(options.keys())
    selected_label = st.selectbox("Select an alert to investigate", labels, index=0)
    selected_id = options[selected_label]
with right_status:
    with st.container(border=True):
        st.caption("GRAPH REPOSITORY STATUS")
        st.markdown(f"**{inventory['nodes']}** nodes · **{inventory['relationships']}** edges")
        st.caption("Live from FalkorDB")

if st.button("⚡ Investigate with graph context", type="primary", use_container_width=True):
    try:
        st.session_state["investigation"] = investigate_alert(graph, selected_id)
        st.session_state["investigated_id"] = selected_id
        st.session_state.pop("brief", None)
        st.rerun()
    except Exception as exc:
        st.error(f"Investigation failed: {type(exc).__name__}: {exc}")

# 6. Pre-investigation state
if "investigation" not in st.session_state or st.session_state.get("investigated_id") != selected_id:
    with st.container(border=True):
        st.markdown("#### Ready to investigate")
        st.markdown("Select an alert above and click **Investigate with graph context** to traverse connected identities, devices, permissions, services, and dependencies in FalkorDB.")

    st.markdown("#### Why graph-first triage?")
    g1, g2, g3 = st.columns(3)
    with g1:
        with st.container(border=True):
            st.markdown("<span class='badge badge-violet'>01 / TRACE</span>", unsafe_allow_html=True)
            st.markdown("**Multi-hop context**")
            st.caption("Follow the alert to its source IP, account, device, assigned roles, cloud project, hosted services, and downstream dependencies.")
    with g2:
        with st.container(border=True):
            st.markdown("<span class='badge badge-violet'>02 / EXPLAIN</span>", unsafe_allow_html=True)
            st.markdown("**Evidence-backed score**")
            st.caption("Every risk point is tied directly to a graph traversal fact; no hallucinated or unexplained model scores.")
    with g3:
        with st.container(border=True):
            st.markdown("<span class='badge badge-violet'>03 / ACT</span>", unsafe_allow_html=True)
            st.markdown("**Auditable response**")
            st.caption("Review proposed containment actions and persist simulated response nodes and relationships back into FalkorDB.")
    st.stop()

# 7. Investigation results
inv = st.session_state["investigation"]
p = inv["primary"]

st.write("")
m1, m2, m3, m4 = st.columns(4)
with m1:
    with st.container(border=True):
        st.caption("RISK SCORE")
        st.markdown(
            f"<div style='display:flex;align-items:center;gap:10px;'><span style='font-size:24px;font-weight:700;'>{inv['score']} <span style='font-size:14px;color:#9ba3b5;'>/ 100</span></span>{risk_badge(inv['risk'])}</div>",
            unsafe_allow_html=True,
        )
        st.caption("Deterministic graph assessment")
with m2:
    with st.container(border=True):
        st.caption("CONNECTED ACCOUNTS")
        st.markdown(f"<span style='font-size:24px;font-weight:700;'>{inv['shared_account_count']}</span>", unsafe_allow_html=True)
        st.caption(f"Linked via IP `{html.escape(str(p['source_ip']))}`")
with m3:
    with st.container(border=True):
        impacted = len({s['service'] for s in inv['services']} | {d['dependency'] for d in inv['dependencies']})
        st.caption("BLAST RADIUS ASSETS")
        st.markdown(f"<span style='font-size:24px;font-weight:700;'>{impacted}</span>", unsafe_allow_html=True)
        st.caption("Services & dependencies in path")
with m4:
    with st.container(border=True):
        st.caption("TARGET IDENTITY")
        st.markdown(f"<span style='font-size:20px;font-weight:700;'>{html.escape(str(p['username']))}</span>", unsafe_allow_html=True)
        st.caption(f"{html.escape(str(p.get('privilege', 'standard')))} privilege · {html.escape(str(p.get('device_trust', 'unknown')))} device")

st.write("")
tab_graph, tab_evidence, tab_agent, tab_actions = st.tabs([
    "◈ Attack Graph",
    "✓ Evidence & Risk",
    "✦ Agent Brief",
    "↗ Response Log",
])

with tab_graph:
    st.markdown("### Relationship map")
    st.caption("Multi-hop graph traversal queried live from FalkorDB. The edges show the exact context paths used by the triage agent.")
    st.graphviz_chart(graphviz_for(inv), use_container_width=True)

    with st.container(border=True):
        st.markdown("##### Node & Edge Legend")
        leg1, leg2, leg3 = st.columns(3)
        with leg1:
            st.markdown(
                "- <span style='display:inline-block;width:10px;height:10px;background:#33203b;border-radius:2px;border:1px solid #633e72;'></span> **Alert**: Root security alert (`#33203b`)<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#40202d;border-radius:2px;border:1px solid #7a3048;'></span> **Source IP (Bad)**: Known-bad reputation (`#40202d`)<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#18302f;border-radius:2px;border:1px solid #285550;'></span> **Source IP (Clean)**: Clean reputation (`#18302f`)",
                unsafe_allow_html=True,
            )
        with leg2:
            st.markdown(
                "- <span style='display:inline-block;width:10px;height:10px;background:#33203b;border-radius:2px;border:1px solid #633e72;'></span> **Account (Admin)**: Elevated privilege (`#33203b`)<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#20283a;border-radius:2px;border:1px solid #364460;'></span> **Account (Standard)**: Standard privilege (`#20283a`)<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#40202d;border-radius:2px;border:1px solid #7a3048;'></span> / <span style='display:inline-block;width:10px;height:10px;background:#18302f;border-radius:2px;border:1px solid #285550;'></span> **Device**: Untrusted (red) / Managed (green)",
                unsafe_allow_html=True,
            )
        with leg3:
            st.markdown(
                "- <span style='display:inline-block;width:10px;height:10px;background:#29264a;border-radius:2px;border:1px solid #48417c;'></span> **Role**: IAM / RBAC permission role<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#1d2f3b;border-radius:2px;border:1px solid #305064;'></span> **Project**: Cloud workspace / environment<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#23352f;border-radius:2px;border:1px solid #3c5e52;'></span> **Service / Dep**: Critical / high asset (`#23352f`)<br>"
                "- <span style='display:inline-block;width:10px;height:10px;background:#40202d;border-radius:2px;border:1px solid #7a3048;'></span> **Indicator**: Threat intel IoC match (`#40202d`)<br>"
                "- <span style='color:#8179d8;font-weight:700;'>──▶</span> **Edges**: FalkorDB relationships (`ORIGINATED_FROM`, `TARGETS`, `CAN_ACCESS`, `HOSTS`, `DEPENDS_ON`, `SEEN_WITH`, `MATCHES_INDICATOR`)",
                unsafe_allow_html=True,
            )

with tab_evidence:
    st.markdown("### Why the agent assigned this score")
    st.markdown(f"Current risk: {risk_badge(inv['risk'])} &nbsp; **{inv['score']}/100**", unsafe_allow_html=True)
    if inv["evidence"]:
        for item in inv["evidence"]:
            st.markdown(
                f"<div class='evidence'><span class='evidence-points'>+{item['points']} POINTS</span><div class='evidence-title'>{html.escape(item['title'])}</div><div class='evidence-detail'>{html.escape(item['detail'])}</div></div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("No configured risk rules fired. Inspect the graph context and expand the rule set with validated evidence.")

    st.markdown("### Matched indicators")
    indicators = inv.get("indicators") or []
    if indicators:
        ind_rows = []
        for ind in indicators:
            ind_rows.append({
                "Indicator": ind.get("value", "N/A"),
                "Type": ind.get("indicator_type", "N/A"),
                "Severity": ind.get("severity") or "N/A",
                "Confidence": ind.get("confidence") or "N/A",
                "Relationship": ind.get("relationship", "MATCHES_INDICATOR"),
                "Description": ind.get("description") or "N/A",
            })
        st.dataframe(ind_rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No threat indicators matched this alert in the graph.")

    st.markdown("### Connected assets")
    rows = []
    for s in inv["services"]:
        rows.append({"Asset": s["service"], "Type": "Service", "Criticality": s["criticality"], "Project": s["project"]})
    for d in inv["dependencies"]:
        rows.append({"Asset": d["dependency"], "Type": f"Dependency of {d['parent_service']}", "Criticality": d["criticality"], "Project": "Inherited dependency"})
    if rows:
        # Keep this table readable and remove exact duplicate rows.
        st.dataframe(list({(r['Asset'], r['Type'], r['Criticality'], r['Project']): r for r in rows}.values()), use_container_width=True, hide_index=True)
    else:
        st.caption("No connected services were returned from the current graph path.")

with tab_agent:
    st.markdown("### Ask the investigation agent")
    st.caption("Graph retrieval is deterministic and grounded in FalkorDB. Set GROQ_API_KEY in .env for optional natural-language synthesis.")
    with st.form("agent_query_form"):
        question = st.text_input("Your question", value="Why is this alert risky, and what should I do first?", placeholder="e.g. What services could be affected?")
        submit_brief = st.form_submit_button("Generate evidence-based brief", type="primary")
    if submit_brief or "brief" not in st.session_state:
        try:
            brief, mode = make_brief(inv, question if "question" in locals() else "Investigate this alert")
            st.session_state["brief"] = brief
            st.session_state["brief_mode"] = mode
        except Exception as exc:
            st.error(f"Could not create the brief: {exc}")
    st.markdown(f"<span class='badge badge-green'>{html.escape(st.session_state.get('brief_mode', 'Evidence grounded'))}</span>", unsafe_allow_html=True)
    st.markdown(st.session_state.get("brief", ""))
    st.caption("Safety boundary: this demo uses synthetic records. It never disables an actual user, changes a cloud account, or performs live containment.")

with tab_actions:
    st.markdown("### Response action")
    st.caption("Persist a simulated containment action node and audit relationships in FalkorDB.")
    with st.container(border=True):
        st.caption("PROPOSED ACTION")
        st.markdown(f"**{html.escape(inv['action'])}**")
    acknowledged = st.checkbox("I understand this records a simulated action only; no real account or service will be changed.", key=f"ack_{selected_id}")
    if st.button("✓ Record simulated response in FalkorDB", disabled=not acknowledged, type="primary"):
        try:
            action = record_response_action(graph, selected_id, p["username"], inv["action"])
            st.success(f"Recorded {action['id']} in FalkorDB with status {action['status']}.")
            st.session_state["last_action"] = action
            st.rerun()
        except Exception as exc:
            st.error(f"Could not record the response action: {type(exc).__name__}: {exc}")
    actions = list_response_actions(graph)
    if actions:
        st.markdown("#### Audit trail — stored in the graph")
        st.dataframe(actions, use_container_width=True, hide_index=True)
    else:
        st.caption("No response actions have been recorded yet.")

# 8. Footer
st.divider()
st.caption("◈ GraphSentry · Evidence-first security investigation agent · Demo data only · Built for Graph Hacks 2026")


if __name__ == "__main__":
    # Enables direct execution with `python app.py` on cloud platforms (Render, Railway, etc.)
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        _in_streamlit = get_script_run_ctx() is not None
    except Exception:
        _in_streamlit = False

    if not _in_streamlit:
        import sys
        from streamlit.web import cli as stcli
        port = os.getenv("PORT", os.getenv("STREAMLIT_SERVER_PORT", "8501"))
        sys.argv = [
            "streamlit",
            "run",
            __file__,
            "--server.port",
            str(port),
            "--server.address",
            "0.0.0.0",
        ]
        sys.exit(stcli.main())
