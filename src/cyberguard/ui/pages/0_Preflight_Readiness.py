import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero

st.set_page_config(page_title="Preflight · CyberGuard AI", page_icon="✓", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Before-work assurance", "Analyst preflight", "Find platform blockers, input risks, and preparation gaps before beginning an investigation or operational change.")

try:
    report = client.preflight()
    health = client.health()
except httpx.HTTPError as exc:
    st.error(f"Preflight could not contact the CyberGuard API: {exc}")
    st.info("Start the API, confirm CYBERGUARD_API_URL, then rerun this page.")
    st.stop()

if report["ready"]:
    st.success("CyberGuard is operationally ready for analysis.")
else:
    st.error("One or more platform blockers must be resolved before analysis.")

st.markdown('<div class="cg-section">Automated checks</div>', unsafe_allow_html=True)
icons = {"pass": "✅", "warn": "⚠️", "fail": "❌"}
for check in report["checks"]:
    with st.container(border=True):
        st.markdown(f'**{icons.get(check["status"], "•")} {check["name"]}**')
        st.write(check["detail"])
        if check.get("action"):
            st.warning(check["action"])

st.markdown('<div class="cg-section">Analysis readiness checklist</div>', unsafe_allow_html=True)
items = [
    "I know which host, service, application or configuration is in scope.",
    "My telemetry covers the relevant time window and includes timestamps.",
    "I removed unnecessary secrets and personal data from the input.",
    "I have authorization, evidence-preservation steps and a rollback plan.",
    "I will validate CyberGuard findings against an independent source.",
]
for item in items:
    st.checkbox(item)

st.markdown('<div class="cg-section">Loaded analysis engine</div>', unsafe_allow_html=True)
a, b, c = st.columns(3)
a.metric("Version", health["version"])
b.metric("Rules", health["rules"])
c.metric("Adapters", len(health["adapters"]))
st.info("Next: open Upload Telemetry. CyberGuard will classify the input, identify whether the likely issue is application, system/infrastructure, configuration, security logs or file integrity, and provide checks and remediation guidance.")
