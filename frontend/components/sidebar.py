import streamlit as st
from frontend.api_client import APIClient

def render_sidebar():
    """Renders clean sidebar with navigation, API connection health badge and session details."""
    with st.sidebar:
        st.markdown("<h2 style='font-size: 1.4rem; color: #FFFFFF; letter-spacing: 1.5px; margin-bottom: 2px;'>NMMVA CORP</h2>", unsafe_allow_html=True)
        st.caption("Banca Digital & Ciberseguridad")
        st.markdown("---")
        
        # Navigation
        st.markdown("<p style='font-size: 0.85rem; font-weight: 700; letter-spacing: 1px; color: rgba(255, 255, 255, 0.7); text-transform: uppercase;'>Navegación</p>", unsafe_allow_html=True)
        current_page = st.session_state.get('current_page', 'landing')
        
        if current_page == "app":
            if st.button("Ir al Inicio (Landing Page)"):
                st.session_state.current_page = "landing"
                st.rerun()
        else:
            if st.button("Ir a Sucursal Virtual"):
                st.session_state.current_page = "app"
                st.rerun()
                
        st.markdown("---")
        
        # Backend Connectivity Ping Check
        st.markdown("<p style='font-size: 0.85rem; font-weight: 700; letter-spacing: 1px; color: rgba(255, 255, 255, 0.7); text-transform: uppercase;'>Estado del Servidor</p>", unsafe_allow_html=True)
        backend_online = APIClient.check_health()
        if backend_online:
            st.success("API Backend: En Línea")
        else:
            st.error("API Backend: Desconectado")
            st.caption("Ejecuta `python run_backend.py` en la terminal.")
            
        st.markdown("---")
        
        # Session State Status
        st.markdown("<p style='font-size: 0.85rem; font-weight: 700; letter-spacing: 1px; color: rgba(255, 255, 255, 0.7); text-transform: uppercase;'>Estado de Sesión</p>", unsafe_allow_html=True)
        if st.session_state.get('id_usuario'):
            st.info(f"Usuario Activo ID: {st.session_state.id_usuario}")
            if st.session_state.get('token_access'):
                st.success("Sesión MFA activa (puedes firmar)")
            else:
                st.caption("Inicia sesión en el Paso 3 para firmar.")
            if st.button("Cerrar Sesión"):
                st.session_state.id_usuario = None
                st.session_state.token_enroll = None
                st.session_state.token_access = None
                st.rerun()
        else:
            st.warning("Sin sesión activa")
            st.caption("Registra una cuenta en el Paso 1.")

        st.markdown("---")
        st.caption("© 2026 NMMVA CORP")
