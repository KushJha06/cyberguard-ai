from collections import Counter

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, metric_card, severity_badge

st.set_page_config(
    page_title="CyberGuard AI · Analyst Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()
sidebar_brand()
client = CyberGuardClient()

try:
    health = client.health()
    incidents = client.incidents(100)
    online = True
except (httpx.HTTPError, ValueError):
    health = {"rules": 0, "adapters": [], "stored_events": 0}
    incidents = []
    online = False

hero(
    "Security operations workspace",
    "Evidence-led triage. Zero autonomous action.",
    "Unify operational and security telemetry, identify likely root cause, and move from signal to a safe, validated response—all while keeping data local.",
    "Analysis engine operational" if online else "API connection unavailable",
)

counts = Counter(item["severity"] for item in incidents)
open_count = sum(1 for item in incidents if item["status"] in {"open", "investigating"})
critical_high = counts["critical"] + counts["high"]
cols = st.columns(4)
with cols[0]:
    metric_card("Open incidents", open_count, "Awaiting analyst disposition", "#38bdf8")
with cols[1]:
    metric_card("Critical + high", critical_high, "Priority investigation queue", "#f97316")
with cols[2]:
    metric_card(
        "Telemetry events", health["stored_events"], "Normalized and stored locally", "#a78bfa"
    )
with cols[3]:
    metric_card("Active detections", health["rules"], "Deterministic explainable rules", "#22c55e")

left, right = st.columns([1.65, 1], gap="large")
with left:
    st.markdown('<div class="cg-section">Latest incident activity</div>', unsafe_allow_html=True)
    if not incidents:
        st.markdown(
            '<div class="cg-empty"><h3>No active findings</h3><p>Upload telemetry to begin evidence-led analysis.</p></div>',
            unsafe_allow_html=True,
        )
    for item in incidents[:5]:
        badge = severity_badge(item["severity"])
        st.markdown(
            f'<div class="cg-card" style="min-height:auto;margin-bottom:.7rem"><div style="display:flex;justify-content:space-between;gap:1rem">'
            f'<div>{badge}<strong style="margin-left:.65rem">{item["title"]}</strong><div class="cg-help" style="margin-top:.55rem">'
            f'{item["summary"]}</div></div><div class="cg-label">{item["event_count"]} signals</div></div></div>',
            unsafe_allow_html=True,
        )
with right:
    st.markdown('<div class="cg-section">Operational posture</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
    <div class="cg-card" style="min-height:250px">
      <div class="cg-label">Platform safeguards</div>
      <div class="cg-rule"><strong>Local persistence</strong><br><small>SQLite evidence store on this host</small></div>
      <div class="cg-rule"><strong>Best-effort redaction</strong><br><small>Common credentials removed before persistence</small></div>
      <div class="cg-rule"><strong>No autonomous remediation</strong><br><small>Every action remains analyst-controlled</small></div>
      <div class="cg-rule"><strong>{len(health["adapters"])} adapters online</strong><br><small>{", ".join(health["adapters"]) or "API offline"}</small></div>
    </div>""",
        unsafe_allow_html=True,
    )

st.markdown('<div class="cg-section">Detection coverage</div>', unsafe_allow_html=True)
coverage = [
    ("Identity", "SSH brute force", "Credential-access patterns"),
    ("Infrastructure", "Capacity & availability", "Disk, memory and service health"),
    ("Application", "HTTP & database failures", "Error-rate and connection-pool signals"),
    ("Configuration", "SSH hardening", "Risky remote-access directives"),
]
columns = st.columns(4)
for col, (domain, title, detail) in zip(columns, coverage, strict=True):
    with col:
        st.markdown(
            f'<div class="cg-card"><div class="cg-label">{domain}</div><div style="font-weight:700;margin:.6rem 0">{title}</div><div class="cg-help">{detail}</div></div>',
            unsafe_allow_html=True,
        )

st.caption(
    "CyberGuard AI provides decision support only. Validate evidence and follow your organization’s change-control procedures."
)
