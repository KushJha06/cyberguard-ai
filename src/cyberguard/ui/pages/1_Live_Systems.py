import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, metric_card

st.set_page_config(page_title="Live Systems · CyberGuard AI", page_icon="◉", layout="wide")
apply_theme()
sidebar_brand()
client = CyberGuardClient()
hero(
    "Real-time operations",
    "Live systems",
    "Read-only host agents stream operating-system health, selected services, application endpoints, logs, configuration and file-integrity signals.",
    "Auto-refreshes every 5 seconds",
)

with st.expander("Connect a system", expanded=False):
    st.markdown("Install CyberGuard on the system, start the API, and run:")
    st.code(
        "cyberguard-agent --api-url http://CYBERGUARD-SERVER:8000 --interval 30", language="bash"
    )
    st.markdown("Optional environment variables:")
    st.code(
        """CYBERGUARD_AGENT_SERVICES=nginx,postgresql
CYBERGUARD_AGENT_HEALTH_URLS=http://localhost:8080/health
CYBERGUARD_AGENT_LOG_PATHS=/var/log/syslog,/var/log/nginx/error.log
CYBERGUARD_AGENT_WATCH_PATHS=/etc/ssh/sshd_config,/etc/passwd
CYBERGUARD_AGENT_TOKEN=replace-with-shared-secret""",
        language="bash",
    )
    st.warning(
        "Run the agent on the host, not only inside the API container. Use TLS and an agent token outside a trusted local network."
    )


@st.fragment(run_every="5s")
def live_grid() -> None:
    try:
        agents = client.agents()
    except httpx.HTTPError as exc:
        st.error(f"Could not retrieve agent status: {exc}")
        return
    if not agents:
        st.info(
            "No live systems have reported yet. Run the command above on a system you want to monitor."
        )
        return
    online = sum(agent["state"] == "online" for agent in agents)
    a, b, c = st.columns(3)
    with a:
        metric_card("Connected systems", len(agents), "Registered monitoring agents", "#38bdf8")
    with b:
        metric_card("Online", online, "Heartbeat within the freshness window", "#22c55e")
    with c:
        metric_card("Stale", len(agents) - online, "Agent requires connectivity review", "#f97316")
    st.markdown('<div class="cg-section">System fleet</div>', unsafe_allow_html=True)
    for agent in agents:
        metrics = agent.get("latest_metrics", {})
        host = metrics.get("host_health", {})
        memory = metrics.get("memory_usage", {})
        disk = metrics.get("disk_usage", {})
        color = "#22c55e" if agent["state"] == "online" else "#f97316"
        with st.container(border=True):
            heading, seen = st.columns([3, 1])
            heading.markdown(
                f'### <span style="color:{color}">●</span> {agent["hostname"]}',
                unsafe_allow_html=True,
            )
            heading.caption(
                f"{agent['platform']} · Agent {agent['agent_version']} · {agent['state'].upper()}"
            )
            seen.caption("LAST HEARTBEAT")
            seen.write(agent["last_seen"].replace("T", " ")[:19] + " UTC")
            cols = st.columns(5)
            cols[0].metric("CPU", f"{host.get('cpu_used_percent', 0):.1f}%")
            cols[1].metric("Memory", f"{memory.get('memory_used_percent', 0):.1f}%")
            cols[2].metric("Disk", f"{disk.get('disk_used_percent', 0):.1f}%")
            cols[3].metric("Processes", host.get("process_count", "—"))
            cols[4].metric("Latest findings", agent["incident_count"])
            if projection := disk.get("projected_minutes_to_full"):
                st.warning(
                    f"Current trend projects disk exhaustion in approximately {projection:.0f} minutes."
                )


live_grid()
st.caption(
    "Monitoring is advisory and read-only. CyberGuard never kills processes, restarts services, deletes files or changes configuration automatically."
)
