import streamlit as st

from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero

st.set_page_config(page_title="User Guide · CyberGuard AI", page_icon="?", layout="wide")
apply_theme()
sidebar_brand()
hero(
    "Product guidance",
    "How to use CyberGuard",
    "Follow an end-to-end workflow from safe demo data to investigation, validation, and export.",
)

st.markdown("## Fastest way to explore every feature")
st.markdown("""
1. Open **Upload Telemetry**.
2. Select **Load complete nine-rule demo**.
3. Open **Overview** to filter and prioritize the resulting incidents.
4. Open **Investigate Incidents**, select an incident, inspect every tab, and update its workflow status.
5. Open **Reports** and export the selected incident as Markdown, HTML, or JSON.
""")

pages = {
    "Live Systems": (
        "Monitor real hosts",
        "Run cyberguard-agent on each host. The page refreshes every five seconds and shows heartbeat state, CPU, memory, disk, process count, findings and capacity projections.",
    ),
    "Overview": (
        "Prioritize findings",
        "Use severity/domain filters and search by title, summary, or rule ID. Metrics summarize the current incident store.",
    ),
    "Investigate Incidents": (
        "Perform analyst triage",
        "Select an incident; review Evidence, Analyst checks, Safe response, Validation, and Limitations. Use Incident workflow to move it between Open, Investigating, Resolved, and False positive.",
    ),
    "Upload Telemetry": (
        "Create incidents from files",
        "Use Auto-detect, choose a supported file, confirm its filename appears, then run analysis. A successful upload can create zero incidents when nothing matches.",
    ),
    "Configuration Scan": (
        "Review SSH posture",
        "Upload an sshd_config-style text file. CyberGuard reports risky directives but does not modify or reload SSH.",
    ),
    "File Integrity": (
        "Assess one sensitive change",
        "Enter host, file path, action, optional SHA-256 and observation. Paths under /etc, /usr/bin, /usr/sbin and Windows System32 trigger the current rule.",
    ),
    "Knowledge Base": (
        "Use local guidance",
        "Browse category playbooks, MITRE technique context and response-safety principles. This content is reference material, not an automated action engine.",
    ),
    "Reports": (
        "Export evidence",
        "Select any stored incident and download an analyst report in Markdown, standalone HTML, or machine-readable JSON.",
    ),
    "Settings": (
        "Inspect runtime state",
        "Review API connectivity, rule count, event count, local database location, upload limit and loaded adapters. Environment settings are read-only in the UI.",
    ),
    "Datasets": (
        "Plan broader evaluation",
        "Search recommended third-party datasets and open their official provider pages. They are catalog entries; CyberGuard does not download or ingest them automatically.",
    ),
}
for page, (purpose, instructions) in pages.items():
    with st.expander(f"{page} — {purpose}"):
        st.write(instructions)

st.markdown("## Supported normalized event example")
st.code(
    """{
  "source": "monitoring",
  "category": "system",
  "event_type": "disk_usage",
  "host": "db-01",
  "message": "Disk utilization high",
  "attributes": {"disk_used_percent": 96, "mount": "/var"}
}""",
    language="json",
)

st.warning(
    "CyberGuard is advisory. Preserve evidence, validate findings independently, obtain authorization, and retain rollback access before making operational changes."
)
