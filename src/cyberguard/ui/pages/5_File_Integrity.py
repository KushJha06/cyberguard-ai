import json

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, severity_badge

st.set_page_config(page_title="File Integrity · CyberGuard AI", page_icon="◇", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Host assurance", "File integrity review", "Assess security-sensitive file changes with explicit context, evidence, and limitations.")

st.markdown('<div class="cg-section">Submit a normalized FIM event</div>', unsafe_allow_html=True)
a, b = st.columns(2)
with a:
    host = st.text_input("Host", placeholder="prod-web-01")
    path = st.text_input("File path", placeholder="/etc/ssh/sshd_config")
with b:
    action = st.selectbox("Observed action", ["modified", "created", "deleted", "permission_changed"])
    sha256 = st.text_input("SHA-256 (optional)", placeholder="64-character digest")
message = st.text_input("Observation", value="File integrity monitor observed a sensitive file change")
if st.button("Analyze change", type="primary", disabled=not (host and path)):
    payload = [{"source":"manual-fim","category":"file_integrity","event_type":"file_change","host":host,
        "message":message,"attributes":{"path":path,"action":action,"sha256":sha256 or None}}]
    try:
        result = client.upload("fim-event.json", json.dumps(payload).encode(), "application/json", "json")
    except httpx.HTTPError as exc: st.error(f"Analysis failed: {exc}")
    else:
        if not result["incidents"]: st.info("The path did not match the current sensitive-path rule set.")
        for item in result["incidents"]:
            st.markdown(f'### {severity_badge(item["severity"])} &nbsp; {item["title"]}', unsafe_allow_html=True)
            st.write(item["summary"])
            with st.expander("Evidence and checks", expanded=True):
                for check in item["analyst_checks"]: st.markdown(f"- {check}")
st.caption("Supported sensitive prefixes: /etc, /usr/bin, /usr/sbin, and C:\\Windows\\System32. Legitimate patching may trigger findings.")
