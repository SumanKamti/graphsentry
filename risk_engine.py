"""Small, deterministic risk engine. Scores only facts retrieved from FalkorDB."""
from __future__ import annotations
from typing import Any


def assess_risk(
    primary: dict[str, Any],
    shared_account_count: int,
    shared_accounts: list[str],
    services: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    indicators: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return score, risk band, evidence list, impact list and recommended next step."""
    score = 0
    evidence: list[dict[str, Any]] = []

    def add_rule(points: int, condition: bool, title: str, detail: str) -> None:
        nonlocal score
        if condition:
            score += points
            evidence.append({"points": points, "title": title, "detail": detail})

    reputation = str(primary.get("reputation", "")).lower()
    privilege = str(primary.get("privilege", "")).lower()
    device_trust = str(primary.get("device_trust", "")).lower()
    add_rule(25, reputation in {"known-bad", "malicious"},
             "Source IP has a known-bad reputation",
             f"FalkorDB marks {primary.get('source_ip')} as {primary.get('reputation')}.")
    add_rule(25, privilege in {"admin", "administrator", "elevated"},
             "Target account has elevated privilege",
             f"{primary.get('username')} has privilege tier '{primary.get('privilege')}'.")
    add_rule(15, device_trust in {"untrusted", "unknown", "compromised"},
             "Login came from an untrusted device",
             f"Device {primary.get('device_id')} has trust status '{primary.get('device_trust')}'.")
    add_rule(20, int(shared_account_count or 0) >= 3,
             "One source is connected to multiple accounts",
             f"The source IP is linked to {shared_account_count} accounts: {', '.join(shared_accounts)}.")

    # Threat indicators rule:
    # An indicator contributes risk only when graph evidence supports high severity or high confidence.
    # Benign, low-severity, or unverified indicators do not receive a risk penalty.
    threat_indicators = []
    for ind in (indicators or []):
        sev = str(ind.get("severity") or "").lower()
        conf = str(ind.get("confidence") or "").lower()
        if sev in {"low", "info", "informational", "benign", "clean"}:
            continue
        if sev in {"critical", "high"} or conf in {"high", "critical"}:
            threat_indicators.append(ind)

    if threat_indicators:
        ind_names = [str(i.get("value") or "unspecified") for i in threat_indicators]
        add_rule(15, True, "Alert matches high-confidence threat indicator",
                 f"FalkorDB linked {len(threat_indicators)} verified threat indicator(s): {', '.join(ind_names)}.")

    critical_services = sorted({
        str(item.get("service")) for item in services
        if str(item.get("criticality", "")).lower() in {"critical", "high"} and item.get("service")
    })
    for item in dependencies:
        dependency = item.get("dependency")
        if (dependency and str(item.get("criticality", "")).lower() in {"critical", "high"}
                and dependency not in critical_services):
            critical_services.append(str(dependency))
    critical_services.sort()
    add_rule(15, bool(critical_services), "Connected project reaches high-impact services",
             "Graph traversal reaches: " + ", ".join(critical_services) + ".")

    score = min(score, 100)
    risk = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    if risk in {"CRITICAL", "HIGH"}:
        action = (f"Contain {primary.get('username')} in a simulated response, preserve the alert evidence, "
                  f"and review every account connected to {primary.get('source_ip')}.")
    elif risk == "MEDIUM":
        action = (f"Require step-up verification for {primary.get('username')} and review the source IP's "
                  "connected accounts before closing the alert.")
    else:
        action = f"Keep {primary.get('username')} under observation and verify that the activity matches the expected workflow."

    return {"score": score, "risk": risk, "evidence": evidence,
            "critical_services": critical_services, "action": action}
