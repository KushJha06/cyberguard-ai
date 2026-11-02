import streamlit as st

from cyberguard.knowledge.mitre import TECHNIQUES
from cyberguard.knowledge.playbooks import PLAYBOOKS
from cyberguard.knowledge.remediation import SAFETY_PRINCIPLES
from cyberguard.ui.components.navigation import sidebar_brand
from cyberguard.ui.components.theme import apply_theme, hero

st.set_page_config(page_title="Knowledge Base · CyberGuard AI", page_icon="▤", layout="wide")
apply_theme()
sidebar_brand()
hero(
    "Analyst enablement",
    "Knowledge base",
    "Use concise local playbooks and ATT&CK context to structure an investigation—not to replace analyst judgment.",
)

tab1, tab2, tab3 = st.tabs(["Response playbooks", "MITRE ATT&CK", "Safety principles"])
with tab1:
    selection = st.selectbox(
        "Playbook", list(PLAYBOOKS), format_func=lambda x: PLAYBOOKS[x]["title"]
    )
    playbook = PLAYBOOKS[selection]
    st.markdown(f"### {playbook['title']}")
    for number, step in enumerate(playbook["steps"], 1):
        st.markdown(
            f'<div class="cg-rule"><strong>{number:02d} · {step}</strong></div>',
            unsafe_allow_html=True,
        )
with tab2:
    for technique_id, technique in TECHNIQUES.items():
        with st.expander(f"{technique_id} · {technique['name']}"):
            st.caption(technique["tactic"].upper())
            st.write(technique["guidance"])
with tab3:
    st.warning("Remediation is advisory and must follow your organization’s authorization process.")
    for principle in SAFETY_PRINCIPLES:
        st.checkbox(principle, value=True, disabled=True)
