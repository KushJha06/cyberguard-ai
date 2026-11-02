import httpx
import streamlit as st

from cyberguard.ui.components.api_client import CyberGuardClient
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero, severity_badge

st.set_page_config(page_title="Configuration Scan · CyberGuard AI", page_icon="⚙", layout="wide")
apply_theme()
sidebar_brand()
client = CyberGuardClient()
hero(
    "Configuration assurance",
    "SSH posture review",
    "Inspect OpenSSH directives for risky authentication and remote-access settings without changing the host.",
)

with st.expander("How to use this scanner"):
    st.write(
        "Upload a text copy of `sshd_config` and select Scan configuration. The scanner checks root login, password authentication, empty passwords, and legacy protocol settings. It does not connect to or modify the server."
    )

left, right = st.columns([1.4, 1], gap="large")
result = None
with left:
    upload = st.file_uploader(
        "Upload sshd_config",
        type=["conf", "config", "txt"],
        help="The scanner ignores comments and never executes content.",
    )
    if upload:
        st.success(f"Ready: {upload.name} · {len(upload.getvalue()) / 1024:,.1f} KB")
    if st.button(
        "Scan uploaded configuration",
        type="primary",
        use_container_width=True,
        disabled=upload is None,
    ):
        try:
            result = client.upload(upload.name, upload.getvalue(), "text/plain", "ssh_config")
        except httpx.HTTPError as exc:
            st.error(f"Scan failed: {exc}")
    if st.button("Scan built-in insecure example", use_container_width=True):
        sample = b"PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords no\n"
        try:
            result = client.upload("demo-sshd.conf", sample, "text/plain", "ssh_config")
        except httpx.HTTPError as exc:
            st.error(f"Scan failed: {exc}")
    if result:
        if not result["incidents"]:
            st.success("No currently implemented insecure SSH patterns were found.")
        for item in result["incidents"]:
            st.markdown(
                f"### {severity_badge(item['severity'])} &nbsp; {item['title']}",
                unsafe_allow_html=True,
            )
            st.write(item["summary"])
            with st.expander("Controlled remediation plan", expanded=True):
                for step in item["remediation"]:
                    st.markdown(f"- {step}")
                st.warning(
                    "Keep the current session open and test a new session before disconnecting."
                )
with right:
    st.markdown('<div class="cg-section">Assurance checklist</div>', unsafe_allow_html=True)
    checks = [
        "Validate syntax with `sshd -t`",
        "Inspect effective values with `sshd -T`",
        "Confirm a key-based break-glass account",
        "Use change control and a rollback window",
    ]
    for item in checks:
        st.checkbox(item, disabled=True)
    st.info(
        "Included files and command-line flags may override the uploaded file. Compare results with effective configuration on the target host."
    )
