import streamlit as st


def sidebar_brand() -> None:
    with st.sidebar:
        st.markdown("""
        <div style="padding:.45rem .2rem 1.2rem">
          <div style="display:flex;align-items:center;gap:.7rem">
            <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#06b6d4,#2563eb);
                 display:grid;place-items:center;color:white;font-weight:900">CG</div>
            <div><strong style="font-size:1rem">CyberGuard AI</strong><br>
            <span style="color:#64748b;font-size:.67rem;letter-spacing:.08em">ANALYST CONSOLE</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.caption("LOCAL-FIRST · ADVISORY ONLY")
