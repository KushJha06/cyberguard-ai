from pathlib import Path

import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, severity_badge

st.set_page_config(page_title="Ingest · CyberGuard AI", page_icon="⇧", layout="wide")
apply_theme(); sidebar_brand(); client = CyberGuardClient()
hero("Ingestion workspace", "Upload telemetry", "Normalize operational and security data, then run all compatible detection rules locally.")

with st.expander("How to use this page", expanded=False):
    st.markdown("""
1. Leave **Adapter** on *Auto-detect*. Known structured formats use their native adapter; other readable text files use safe universal inspection.
2. Drop any file into the uploader and verify its name and size appear below it. Binary files are never executed and will receive export/conversion guidance.
3. Select **Run analysis**. Successful findings become available in Overview, Investigate Incidents, and Reports.
4. If you do not have a compatible file, use **Load complete demo** to create all nine incident types.

CSV requires the columns `source`, `category`, `event_type`, `message`, and optional `timestamp`, `host`, `service`. Additional columns become event attributes.
""")

left, right = st.columns([1.55, 1], gap="large")
with left:
    st.markdown('<div class="cg-section">New analysis run</div>', unsafe_allow_html=True)
    adapter_label = st.selectbox("Adapter", ["Auto-detect", "CSV telemetry", "JSON / JSONL events", "OpenSSH configuration"])
    adapter_map = {"Auto-detect": None, "CSV telemetry": "csv", "JSON / JSONL events": "json",
        "OpenSSH configuration": "ssh_config"}
    upload = st.file_uploader("Drop a file here or browse",
        help="CyberGuard safely inspects any filename. Text logs, CSV, JSON, JSONL and configurations are analyzed; unsupported binary formats receive conversion guidance.")
    if upload:
        size_kb = len(upload.getvalue()) / 1024
        st.success(f"Ready: {upload.name} · {size_kb:,.1f} KB")
        if adapter_label == "Auto-detect":
            inferred = {".csv":"CSV", ".json":"JSON", ".jsonl":"JSONL", ".conf":"SSH configuration",
                ".config":"SSH configuration", ".txt":"Universal text inspection", ".log":"Universal log inspection"}.get(
                    Path(upload.name).suffix.lower(), "Universal safe inspection")
            st.caption(f"Detected format: {inferred}")
    analyze = st.button("Run analysis", type="primary", use_container_width=True, disabled=upload is None)
    st.divider()
    st.markdown("**No file available?** Load a safe built-in scenario that exercises every detection and fills the investigation workspace.")
    load_demo = st.button("Load complete nine-rule demo", use_container_width=True)
with right:
    st.markdown('<div class="cg-section">Supported input</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="cg-card" style="min-height:290px">
      <div class="cg-rule"><strong>CSV telemetry</strong><br><small>System, application, authentication and file events</small></div>
      <div class="cg-rule"><strong>JSON / JSONL</strong><br><small>Normalized TelemetryEvent objects or an events array</small></div>
      <div class="cg-rule"><strong>OpenSSH configuration</strong><br><small>sshd_config text for non-invasive posture review</small></div>
      <div class="cg-rule"><strong>Local and advisory</strong><br><small>Best-effort redaction; no uploaded content is executed</small></div>
    </div>""", unsafe_allow_html=True)

result = None
if analyze and upload:
    with st.status("Running CyberGuard analysis…", expanded=True) as status:
        st.write("Uploading and validating the selected file…")
        try:
            result = client.upload(upload.name, upload.getvalue(), upload.type or "application/octet-stream",
                adapter_map[adapter_label])
        except httpx.HTTPStatusError as exc:
            status.update(label="Analysis rejected", state="error")
            detail = exc.response.json().get("detail", exc.response.text) if exc.response.content else str(exc)
            st.error(f"Upload failed: {detail}")
        except httpx.HTTPError as exc:
            status.update(label="API unavailable", state="error")
            st.error(f"Could not reach {client.base_url}: {exc}")
        else:
            status.update(label="Analysis complete", state="complete", expanded=False)
if load_demo:
    with st.spinner("Creating the complete demonstration workspace…"):
        try:
            result = client.load_demo()
        except httpx.HTTPError as exc:
            st.error(f"Could not load the demo: {exc}")

if result:
    st.success(f'Accepted {result["accepted_events"]} events and created {len(result["incidents"])} incidents in {result.get("processing_ms", 0):.1f} ms.')
    diagnosis = result.get("diagnosis")
    if diagnosis:
        st.markdown('<div class="cg-section">Analyst readiness assessment</div>', unsafe_allow_html=True)
        readiness_color = {"ready": "#22c55e", "review": "#f59e0b", "blocked": "#ef4444"}.get(
            diagnosis["readiness"], "#38bdf8")
        st.markdown(f'<div class="cg-card" style="border-left:4px solid {readiness_color}"><div class="cg-label">'
            f'{diagnosis["readiness"].upper()} · {diagnosis["primary_issue_area"].replace("_", " ").upper()}</div>'
            f'<div style="margin-top:.65rem">{diagnosis["summary"]}</div></div>', unsafe_allow_html=True)
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Likely causes**")
            for cause in diagnosis["likely_causes"] or ["No likely cause identified by current rules."]:
                st.markdown(f"- {cause}")
        with d2:
            st.markdown("**Before you begin**")
            for action in diagnosis["recommended_actions"]:
                st.markdown(f"- {action}")
    if not result["incidents"]:
        st.info("The upload succeeded, but no active rule matched these events. This is a valid result.")
    for incident in result["incidents"]:
        with st.container(border=True):
            st.markdown(f'{severity_badge(incident["severity"])} &nbsp; **{incident["title"]}**', unsafe_allow_html=True)
            st.write(incident["summary"])
            st.caption(f'Confidence {incident["confidence"]:.0%} · {incident["event_count"]} evidence items')
    st.page_link("pages/2_Investigate_Incidents.py", label="Open investigation workspace →")
