import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, empty_state, hero, severity_badge

st.set_page_config(page_title="Investigate · CyberGuard AI", page_icon="⌕", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Analyst workspace", "Investigate incidents", "Move from observed signals to likely cause, controlled response, and explicit validation.")
try:
    incidents = client.incidents()
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Could not reach the API: {exc}"); st.stop()
if not incidents:
    empty_state("The queue is clear", "Upload telemetry to generate an evidence-led incident."); st.stop()

selected = st.selectbox("Select investigation", incidents,
    format_func=lambda x: f'{x["severity"].upper()}  ·  {x["title"]}  ·  {x["id"][:8]}')
header, meta = st.columns([4, 1])
with header:
    st.markdown(f'## {selected["title"]} &nbsp; {severity_badge(selected["severity"])}', unsafe_allow_html=True)
    st.write(selected["summary"])
with meta:
    st.metric("Confidence", f'{selected["confidence"]:.0%}')
    st.caption(f'{selected["event_count"]} evidence items')

with st.expander("Incident workflow"):
    workflow, action = st.columns([3, 1])
    states = ["open", "investigating", "resolved", "false_positive"]
    next_status = workflow.selectbox("Disposition", states, index=states.index(selected["status"]),
        format_func=lambda value: value.replace("_", " ").title())
    if action.button("Update status", type="primary", use_container_width=True):
        try:
            selected = client.update_status(selected["id"], next_status)
            st.success(f'Incident moved to {next_status.replace("_", " ")}')
        except httpx.HTTPError as exc:
            st.error(f"Status update failed: {exc}")

st.markdown('<div class="cg-section">Assessment</div>', unsafe_allow_html=True)
st.info(selected["root_cause"], icon="◎")
tabs = st.tabs(["Evidence", "Analyst checks", "Safe response", "Validation", "Limitations"])
with tabs[0]:
    for number, evidence in enumerate(selected["evidence"], 1):
        with st.container(border=True):
            st.caption(f"EVIDENCE {number:02d}" + (f' · EVENT {evidence["event_id"][:8]}' if evidence.get("event_id") else ""))
            st.code(evidence["summary"], language=None)
            if evidence.get("details"): st.json(evidence["details"], expanded=False)
with tabs[1]:
    for number, value in enumerate(selected["analyst_checks"], 1): st.markdown(f"**{number:02d}** &nbsp; {value}")
with tabs[2]:
    st.warning("Obtain authorization and preserve rollback access before making changes.")
    for number, value in enumerate(selected["remediation"], 1): st.markdown(f"**{number:02d}** &nbsp; {value}")
with tabs[3]:
    for value in selected["validation"]: st.checkbox(value, key=f'{selected["id"]}-{value}')
with tabs[4]:
    for value in selected["limitations"]: st.markdown(f"- {value}")

footer_cols = st.columns(3)
footer_cols[0].caption("RULES · " + ", ".join(selected["rule_ids"]))
footer_cols[1].caption("STATUS · " + selected["status"].upper())
footer_cols[2].caption("MITRE · " + (", ".join(selected["mitre_techniques"]) or "NOT MAPPED"))
