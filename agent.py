"""Grounded analyst briefing for GraphSentry; Groq is optional."""
from __future__ import annotations

import os
from typing import Any


def make_brief(investigation: dict[str, Any], question: str = "Investigate this alert") -> tuple[str, str]:
    """Return (brief, mode). Any LLM output is constrained to graph-derived evidence."""
    p = investigation["primary"]
    services = sorted({x["service"] for x in investigation["services"]})
    services += sorted({x["dependency"] for x in investigation["dependencies"] if x["dependency"] not in services})
    indicators = investigation.get("indicators") or []
    ind_summary = ", ".join(f"{i['value']} ({i.get('indicator_type') or 'indicator'})" for i in indicators) if indicators else "none"
    evidence_lines = [f"+{e['points']} — {e['title']}: {e['detail']}" for e in investigation["evidence"]]
    evidence_text = "\n".join(evidence_lines) if evidence_lines else "No configured risk rule fired from the returned graph evidence."
    fallback = (
        f"**{investigation['risk']} risk ({investigation['score']}/100).** "
        f"Alert {p['alert_id']} targets `{p['username']}` from `{p['source_ip']}`. "
        f"The graph connects the source to {investigation['shared_account_count']} account(s) "
        f"({', '.join(investigation['shared_accounts']) or 'none returned'}), "
        f"matched threat indicator(s): {ind_summary}, and to these services/dependencies: "
        f"{', '.join(services) or 'no services returned'}.\n\n"
        f"**Why:**\n" + "\n".join(f"- {e['title']} (+{e['points']}): {e['detail']}" for e in investigation["evidence"])
        + f"\n\n**Recommended next step:** {investigation['action']}\n\n"
        "This assessment uses synthetic demo data. The containment action is simulated and does not change a real account."
    )
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return fallback, "Evidence-grounded fallback"
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        prompt = f"""You are GraphSentry, a careful security triage agent. Answer the user's request using ONLY the graph evidence below. Do not invent facts or claim a real-world system was accessed. Clearly separate observed facts from recommendations. Include the risk score and cite evidence by naming the graph fact. If evidence is missing, say so. Be concise and readable.

User request: {question}
Alert context: {p}
Matched indicators: {ind_summary}
Connected accounts: {investigation['shared_accounts']}
Connected services: {services}
Risk score: {investigation['score']}/100 ({investigation['risk']})
Risk evidence:
{evidence_text}
Recommended next step: {investigation['action']}
"""
        response = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            messages=[
                {"role": "system", "content": "Be an evidence-bound security analyst. Graph results are the source of truth."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )
        answer = response.choices[0].message.content
        if answer:
            return answer, "Groq + FalkorDB evidence"
    except Exception as exc:
        # Keep the prototype available even with a missing, expired, or rate-limited key.
        return fallback + f"\n\n*LLM summary unavailable; displayed deterministic evidence summary instead ({type(exc).__name__}).*", "Evidence-grounded fallback"
    return fallback, "Evidence-grounded fallback"
