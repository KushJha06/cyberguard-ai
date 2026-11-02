from collections import Counter

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, metric_card

st.set_page_config(page_title="Integrations · CyberGuard AI", page_icon="⌘", layout="wide")
apply_theme()
sidebar_brand()
client = CyberGuardClient()
hero(
    "Open ecosystem",
    "Integrations & plugins",
    "Extend CyberGuard through versioned Python entry points without modifying the core application.",
    "Plugin API v1",
)

try:
    plugins = client.plugins()
except httpx.HTTPError as exc:
    st.error(f"Could not load plugin inventory: {exc}")
    st.stop()

counts = Counter(item["kind"] for item in plugins if item["status"] == "loaded")
external = sum(item["source"] == "external" for item in plugins)
failed = sum(item["status"] == "failed" for item in plugins)
cols = st.columns(4)
with cols[0]:
    metric_card(
        "Detection plugins", counts["detection"], "Rules available to the engine", "#a78bfa"
    )
with cols[1]:
    metric_card("Adapter plugins", counts["adapter"], "Telemetry normalization sources", "#38bdf8")
with cols[2]:
    metric_card("External packages", external, "Installed community extensions", "#22c55e")
with cols[3]:
    metric_card(
        "Plugin errors",
        failed,
        "Extensions requiring attention",
        "#ef4444" if failed else "#22c55e",
    )

build, connect = st.tabs(["Plugin inventory", "Integration patterns"])
with build:
    filter_cols = st.columns(2)
    source = filter_cols[0].selectbox("Source", ["All", "Built-in", "External"])
    kind = filter_cols[1].selectbox("Capability", ["All", "Detection", "Adapter"])
    filtered = [
        item
        for item in plugins
        if (source == "All" or item["source"] == source.lower())
        and (kind == "All" or item["kind"] == kind.lower())
    ]
    for item in filtered:
        color = "#22c55e" if item["status"] == "loaded" else "#ef4444"
        with st.container(border=True):
            a, b = st.columns([4, 1])
            a.markdown(
                f'**{item["id"]}** &nbsp; <span class="cg-badge" style="color:{color};border:1px solid {color}55">{item["status"]}</span>',
                unsafe_allow_html=True,
            )
            a.caption(f"{item['kind'].upper()} · {item['source'].upper()} · {item['distribution']}")
            b.code(item["version"], language=None)
            if item.get("detail"):
                st.error(item["detail"])
with connect:
    integrations = [
        (
            "Wazuh",
            "Normalize alerts and file-integrity events through an adapter plugin.",
            "Adapter",
        ),
        ("Zeek", "Map conn, dns, http and notice logs into network telemetry.", "Adapter"),
        (
            "OpenTelemetry",
            "Receive application logs, metrics and traces through a collector bridge.",
            "Adapter",
        ),
        (
            "TheHive",
            "Create or enrich analyst cases through an outbound integration.",
            "Integration",
        ),
        (
            "OpenSearch",
            "Index normalized incidents and evidence for fleet-scale search.",
            "Integration",
        ),
        (
            "Slack / Jira",
            "Send reviewed incident notifications or create tracked work items.",
            "Integration",
        ),
    ]
    cards = st.columns(3)
    for index, (name, detail, capability) in enumerate(integrations):
        with cards[index % 3]:
            st.markdown(
                f'<div class="cg-card" style="margin-bottom:1rem"><div class="cg-label">{capability}</div><div style="font-size:1.05rem;font-weight:750;margin:.55rem 0">{name}</div><div class="cg-help">{detail}</div></div>',
                unsafe_allow_html=True,
            )

st.markdown('<div class="cg-section">Create a community plugin</div>', unsafe_allow_html=True)
st.code(
    '''[project.entry-points."cyberguard.adapters"]
my_source = "my_package.adapter:MyAdapter"

[project.entry-points."cyberguard.detections"]
my_rule = "my_package.rule:MyDetectionRule"''',
    language="toml",
)
st.info(
    "Only install trusted plugins. Python entry points execute package code inside the CyberGuard process. Review source, pin versions, and test plugins before deployment."
)
