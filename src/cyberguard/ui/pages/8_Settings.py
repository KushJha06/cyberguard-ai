import os

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, metric_card

st.set_page_config(page_title="Settings · CyberGuard AI", page_icon="⚙", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Platform administration", "Settings & diagnostics", "Review runtime connectivity, local safety controls, and loaded analysis capabilities.")
try: health = client.health(); online = True
except httpx.HTTPError: health = {"rules":0,"adapters":[],"stored_events":0}; online = False
cols = st.columns(3)
with cols[0]: metric_card("API status", "Online" if online else "Offline", client.base_url, "#22c55e" if online else "#ef4444")
with cols[1]: metric_card("Rules loaded", health["rules"], "Deterministic detection modules", "#38bdf8")
with cols[2]: metric_card("Events stored", health["stored_events"], "Local SQLite evidence store", "#a78bfa")
st.markdown('<div class="cg-section">Runtime configuration</div>', unsafe_allow_html=True)
st.text_input("API endpoint", client.base_url, disabled=True)
st.text_input("Database path", os.getenv("CYBERGUARD_DATABASE_PATH", "data/runtime/cyberguard.db"), disabled=True)
a, b = st.columns(2)
a.checkbox("Sensitive-value redaction", value=os.getenv("CYBERGUARD_REDACT_SENSITIVE", "true").lower() == "true", disabled=True)
b.number_input("Upload limit (MB)", value=int(os.getenv("CYBERGUARD_MAX_UPLOAD_BYTES", "10485760")) // 1048576, disabled=True)
st.caption("Runtime values are configured through CYBERGUARD_* environment variables and require a service restart.")
st.markdown('<div class="cg-section">Loaded capabilities</div>', unsafe_allow_html=True)
st.code("Adapters: " + ", ".join(health["adapters"]) + f"\nDetection rules: {health['rules']}", language=None)
st.warning("The MVP does not include authentication. Do not expose the API directly to an untrusted network.")
