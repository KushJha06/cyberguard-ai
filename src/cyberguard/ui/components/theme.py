from html import escape

import streamlit as st

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#22c55e",
    "info": "#38bdf8",
}


def apply_theme() -> None:
    st.markdown(
        """
<style>
:root { --cg-cyan:#22d3ee; --cg-blue:#3b82f6; --cg-panel:#111827; --cg-border:#243044; }
html, body, [class*="css"] { font-family: Inter, system-ui, sans-serif; }
.stApp { background: radial-gradient(circle at 82% -10%, #102a43 0, #07111f 35%, #050b14 78%); }
[data-testid="stSidebar"] { background:#07101d; border-right:1px solid #1e293b; }
[data-testid="stSidebarNav"] span { font-weight:600; }
.block-container { max-width:1440px; padding-top:2.1rem; padding-bottom:4rem; }
#MainMenu, footer { visibility:hidden; }
h1, h2, h3 { letter-spacing:-.025em; }
h1 { font-weight:800 !important; }
.cg-kicker { color:#22d3ee; font-size:.72rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
.cg-hero { padding:2rem 2.2rem; border:1px solid #243044; border-radius:22px;
 background:linear-gradient(125deg,rgba(18,38,62,.96),rgba(8,18,32,.96)); margin-bottom:1.4rem;
 box-shadow:0 18px 60px rgba(0,0,0,.22); position:relative; overflow:hidden; }
.cg-hero:after { content:''; position:absolute; width:280px; height:280px; right:-100px; top:-150px;
 border:48px solid rgba(34,211,238,.07); border-radius:50%; }
.cg-hero h1 { margin:.35rem 0 .45rem; font-size:2.35rem; }
.cg-hero p { color:#a8b5c7; max-width:780px; font-size:1rem; line-height:1.7; margin:0; }
.cg-card { background:linear-gradient(145deg,rgba(17,24,39,.96),rgba(10,18,30,.96)); border:1px solid #243044;
 border-radius:16px; padding:1.15rem 1.25rem; min-height:120px; box-shadow:0 10px 35px rgba(0,0,0,.14); }
.cg-card:hover { border-color:#36516e; transform:translateY(-1px); transition:.2s ease; }
.cg-label { color:#8492a6; text-transform:uppercase; letter-spacing:.1em; font-size:.67rem; font-weight:700; }
.cg-value { color:#f8fafc; font-size:1.75rem; font-weight:800; margin:.35rem 0 .15rem; }
.cg-help { color:#7f8da3; font-size:.76rem; }
.cg-status { display:inline-flex; align-items:center; gap:.45rem; padding:.35rem .65rem; border-radius:999px;
 background:rgba(34,197,94,.1); color:#86efac; border:1px solid rgba(34,197,94,.25); font-size:.72rem; font-weight:700; }
.cg-dot { width:7px; height:7px; border-radius:50%; background:#22c55e; box-shadow:0 0 10px #22c55e; }
.cg-badge { display:inline-block; border-radius:999px; padding:.25rem .58rem; font-size:.68rem; font-weight:800;
 letter-spacing:.05em; text-transform:uppercase; }
.cg-section { color:#d9e4f2; font-size:1.05rem; font-weight:700; margin:1.8rem 0 .85rem; }
.cg-rule { padding:.85rem 1rem; border-left:3px solid #22d3ee; background:rgba(17,24,39,.72); border-radius:0 10px 10px 0; margin:.45rem 0; }
.cg-rule strong { color:#e5edf7; } .cg-rule small { color:#8090a6; }
.cg-empty { text-align:center; padding:3.6rem 1rem; border:1px dashed #334155; border-radius:18px; color:#8291a6; }
div[data-testid="stMetric"] { background:rgba(17,24,39,.85); border:1px solid #243044; padding:1rem; border-radius:14px; }
div[data-testid="stMetricLabel"] { color:#8796aa; }
.stButton>button { border-radius:10px; font-weight:700; border:1px solid #28465f; }
.stButton>button[kind="primary"] { background:linear-gradient(90deg,#0891b2,#2563eb); border:0; }
[data-testid="stFileUploader"] { background:rgba(10,18,30,.75); border:1px dashed #35506d; border-radius:16px; padding:.5rem; }
[data-baseweb="tab-list"] { gap:.4rem; border-bottom:1px solid #263246; }
[data-baseweb="tab"] { border-radius:8px 8px 0 0; font-weight:600; }
</style>
""",
        unsafe_allow_html=True,
    )


def hero(kicker: str, title: str, description: str, status: str | None = None) -> None:
    status_html = ""
    if status:
        status_html = f'<div style="margin-top:1rem"><span class="cg-status"><i class="cg-dot"></i>{escape(status)}</span></div>'
    st.markdown(
        f'<section class="cg-hero"><div class="cg-kicker">{escape(kicker)}</div><h1>{escape(title)}</h1>'
        f"<p>{escape(description)}</p>{status_html}</section>",
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str | int, help_text: str, accent: str = "#22d3ee") -> None:
    st.markdown(
        f'<div class="cg-card" style="border-top:2px solid {accent}"><div class="cg-label">{escape(label)}</div>'
        f'<div class="cg-value">{escape(str(value))}</div><div class="cg-help">{escape(help_text)}</div></div>',
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.lower(), "#64748b")
    return (
        f'<span class="cg-badge" style="color:{color};background:{color}18;border:1px solid {color}55">'
        f"{escape(severity)}</span>"
    )


def empty_state(title: str, message: str) -> None:
    st.markdown(
        f'<div class="cg-empty"><h3>{escape(title)}</h3><p>{escape(message)}</p></div>',
        unsafe_allow_html=True,
    )
