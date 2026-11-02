import httpx
import streamlit as st

from cyberguard.core.models import Incident
from cyberguard.reporting.incident_report import incident_html, incident_markdown
from cyberguard.reporting.json_export import export_incident
from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, empty_state, hero, severity_badge

st.set_page_config(page_title="Reports · CyberGuard AI", page_icon="▧", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Evidence export", "Incident reports", "Create portable analyst-ready reports while preserving findings, safeguards, and known limitations.")
try: incidents = client.incidents()
except httpx.HTTPError as exc: st.error(f"Could not reach the API: {exc}"); st.stop()
if not incidents: empty_state("Nothing to report", "Analyze telemetry to create the first incident report."); st.stop()
selected = st.selectbox("Incident", incidents, format_func=lambda x: f'{x["severity"].upper()} · {x["title"]} · {x["id"][:8]}')
incident = Incident.model_validate(selected)
st.markdown(f'## {severity_badge(incident.severity.value)} &nbsp; {incident.title}', unsafe_allow_html=True)
st.write(incident.summary)
cols = st.columns(3)
cols[0].download_button("Download Markdown", incident_markdown(incident), f"incident-{incident.id[:8]}.md", "text/markdown", use_container_width=True)
cols[1].download_button("Download HTML", incident_html(incident), f"incident-{incident.id[:8]}.html", "text/html", use_container_width=True)
cols[2].download_button("Download JSON", export_incident(incident), f"incident-{incident.id[:8]}.json", "application/json", use_container_width=True)
with st.expander("Report preview", expanded=True): st.markdown(incident_markdown(incident))
