import streamlit as st
import os
import base64

def render_header():
    """Renders header with title on left and bank logo image in top right corner for Virtual Branch."""
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "..", "assets", "fondo_banco.png"),
        os.path.join(os.path.dirname(__file__), "..", "..", "fondo banco.png"),
        "frontend/assets/fondo_banco.png",
        "fondo banco.png"
    ]
    
    logo_b64 = None
    for path in possible_paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("utf-8")
            break

    col_title, col_logo = st.columns([3, 1])

    with col_title:
        st.markdown("""
            <div style="padding-top: 5px;">
                <h2 style="margin: 0; font-size: 1.6rem; color: #FFFFFF; letter-spacing: 2px;">SUCURSAL VIRTUAL NMMVA CORP</h2>
                <p style="margin-top: 6px; margin-bottom: 0; font-size: 0.88rem; color: rgba(255, 255, 255, 0.85); letter-spacing: 0.5px;">
                    Plataforma de Apertura de Cuenta, Autenticación 2FA y Firma Digital Criptográfica
                </p>
            </div>
        """, unsafe_allow_html=True)

    with col_logo:
        if logo_b64:
            st.markdown(f"""
                <div style="text-align: right;">
                    <img src="data:image/png;base64,{logo_b64}" style="width: 100%; max-width: 170px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.6);" alt="NMMVA Logo" />
                </div>
            """, unsafe_allow_html=True)

    st.markdown("<hr style='margin-top: 15px; margin-bottom: 25px;'>", unsafe_allow_html=True)
