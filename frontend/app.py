import streamlit as st
import os
from frontend.components.header import render_header
from frontend.components.sidebar import render_sidebar
from frontend.views.landing_view import render_landing_view
from frontend.views.registration_view import render_registration_view
from frontend.views.totp_view import render_totp_view
from frontend.views.signature_view import render_signature_view

# Page Configuration - Removed bank emoji from page_icon per user request
st.set_page_config(
    page_title="NMMVA CORP - Banco Digital", 
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Load CSS Stylesheet
css_path = os.path.join(os.path.dirname(__file__), "assets", "styles.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Session state initialization
if 'id_usuario' not in st.session_state:
    st.session_state.id_usuario = None

if 'current_page' not in st.session_state:
    st.session_state.current_page = "landing"

# Render Sidebar
render_sidebar()

# Page Routing: Landing Page vs Virtual Branch
if st.session_state.current_page == "landing":
    render_landing_view()
else:
    render_header()
    tab1, tab2, tab3 = st.tabs(["1. Registro", "2. Configurar TOTP (2FA)", "3. Firma con 2FA"])

    with tab1:
        render_registration_view()

    with tab2:
        render_totp_view()

    with tab3:
        render_signature_view()
