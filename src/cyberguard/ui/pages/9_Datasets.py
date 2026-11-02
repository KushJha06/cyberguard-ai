import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero

st.set_page_config(page_title="Datasets · CyberGuard AI", page_icon="◈", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Evaluation laboratory", "Dataset catalog", "Plan reproducible backend evaluation with authoritative public security and operations datasets.")
try:
    datasets = client.datasets()
except httpx.HTTPError as exc:
    st.error(f"Could not load the dataset catalog: {exc}"); st.stop()

st.info("CyberGuard links to official provider pages but does not automatically download or redistribute large third-party datasets. Review terms before use.")
search = st.text_input("Search catalog", placeholder="network, authentication, system logs…")
filtered = [item for item in datasets if not search or search.lower() in
    (item["name"] + item["provider"] + " ".join(item["domains"])).lower()]
for item in filtered:
    with st.container(border=True):
        left, right = st.columns([3, 1])
        with left:
            st.markdown(f'### {item["name"]}')
            st.caption(item["provider"] + " · " + " / ".join(item["domains"]).upper())
            st.write(item["recommended_use"])
            st.caption(f'Formats: {", ".join(item["formats"])} · {item["size_note"]}')
            st.caption("Terms: " + item["license_note"])
        with right:
            st.markdown(f'**Adapter:** `{item["adapter_status"]}`')
            st.link_button("Official dataset page", item["homepage"], use_container_width=True)

st.markdown('<div class="cg-section">Recommended integration order</div>', unsafe_allow_html=True)
st.markdown("1. **Loghub 2.0** for parser and operational anomaly evaluation.\n2. **UNSW-NB15** for network rules.\n3. **CIC-IDS2017** for flow-based attack coverage.\n4. **LANL** for large-scale authentication and host correlation.\n5. **ToN-IoT** for heterogeneous telemetry.")
