from collections import Counter
from datetime import datetime

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import (
    apply_theme,
    empty_state,
    hero,
    metric_card,
    severity_badge,
)

st.set_page_config(page_title="Overview · CyberGuard AI", page_icon="◫", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Command center", "Incident overview", "Prioritize the investigation queue by severity, domain, and evidence confidence.")
try:
    incidents = client.incidents()
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Could not reach the CyberGuard API: {exc}"); st.stop()

counts = Counter(i["severity"] for i in incidents)
cols = st.columns(5)
palette = {"critical":"#ef4444","high":"#f97316","medium":"#f59e0b","low":"#22c55e","info":"#38bdf8"}
for col, severity in zip(cols, palette, strict=True):
    with col: metric_card(severity.title(), counts[severity], "incident findings", palette[severity])

st.markdown('<div class="cg-section">Investigation queue</div>', unsafe_allow_html=True)
filter_cols = st.columns([1, 1, 1.4])
severity_filter = filter_cols[0].multiselect("Severity", list(palette), default=[])
category_filter = filter_cols[1].multiselect("Domain", sorted({i["category"] for i in incidents}), default=[])
query = filter_cols[2].text_input("Search", placeholder="Title, summary, rule ID…")
filtered = [i for i in incidents if (not severity_filter or i["severity"] in severity_filter)
    and (not category_filter or i["category"] in category_filter)
    and (not query or query.lower() in (i["title"] + i["summary"] + " ".join(i["rule_ids"])).lower())]
if not filtered:
    empty_state("No incidents match", "Adjust the filters or upload telemetry to create a new analysis run.")
for item in filtered:
    created = datetime.fromisoformat(item["created_at"]).strftime("%d %b · %H:%M UTC")
    with st.container(border=True):
        a, b, c = st.columns([4, 1.1, 1.2])
        with a:
            st.markdown(f'{severity_badge(item["severity"])} &nbsp; **{item["title"]}**', unsafe_allow_html=True)
            st.caption(item["summary"])
        b.metric("Confidence", f'{item["confidence"]:.0%}')
        c.metric("Evidence", item["event_count"])
        st.caption(f'{item["category"].replace("_", " ").title()} · {created} · {item["status"].replace("_", " ").title()} · {", ".join(item["rule_ids"])}')
