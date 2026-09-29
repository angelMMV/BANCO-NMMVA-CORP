import streamlit as st
import os
import base64

def render_landing_view():
    """Renders the Landing Page with fondo_banco.png as the first hero element at the top, and info text below on scroll."""
    
    # Locate and Base64-encode the banner image (fondo_banco.png / fondo banco.png)
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "..", "assets", "fondo_banco.png"),
        os.path.join(os.path.dirname(__file__), "..", "..", "fondo banco.png"),
        "frontend/assets/fondo_banco.png",
        "fondo banco.png"
    ]
    
    banner_b64 = None
    for path in possible_paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                banner_b64 = base64.b64encode(f.read()).decode("utf-8")
            break

    # 1. First Thing the User Sees: Top Hero Image (fondo banco.png)
    if banner_b64:
        st.markdown(f"""
            <div style="width: 100%; text-align: center; margin-top: 0; margin-bottom: 40px;">
                <img src="data:image/png;base64,{banner_b64}" style="width: 100%; max-width: 900px; border-radius: 12px; box-shadow: 0 10px 35px rgba(0, 0, 0, 0.85); display: block; margin: 0 auto;" alt="NMMVA Bank & Corp." />
            </div>
        """, unsafe_allow_html=True)

    # 2. Information Section (Shown as the user scrolls down)
    st.markdown("""
        <div style="text-align: center; padding: 10px 0 25px 0;">
            <h1 class="hero-title">NMMVA CORP</h1>
            <p class="hero-subtitle">« El futuro de tus finanzas, blindado hoy. »</p>
            <p class="hero-description">
                Somos un neobanco 100% digital diseñado para ofrecer la máxima agilidad financiera sin comprometer la seguridad. 
                Cada operación en NMMVA CORP está respaldada por Autenticación de Doble Factor (2FA TOTP) y 
                Firma Digital Criptográfica SHA-256, garantizando trazabilidad total e inmutabilidad de No-Repudio.
            </p>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)

    # 3 Pillars as clean text columns
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
            <div style="text-align: center; padding: 10px;">
                <h4 style="color: #FFFFFF; font-size: 1.1rem; margin-bottom: 10px; font-weight: 700;">Seguridad 2FA TOTP</h4>
                <p style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.85); line-height: 1.6;">
                    Protección biométrica-temporal compatible con Google y Microsoft Authenticator bajo el estándar RFC 6238.
                </p>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
            <div style="text-align: center; padding: 10px;">
                <h4 style="color: #FFFFFF; font-size: 1.1rem; margin-bottom: 10px; font-weight: 700;">Firma Criptográfica</h4>
                <p style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.85); line-height: 1.6;">
                    Emisión de sellos digitales SHA-256 para contratos bancarios con garantía técnica de No-Repudio.
                </p>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
            <div style="text-align: center; padding: 10px;">
                <h4 style="color: #FFFFFF; font-size: 1.1rem; margin-bottom: 10px; font-weight: 700;">Banca 100% Virtual</h4>
                <p style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.85); line-height: 1.6;">
                    Apertura de cuenta e interacción inmediata sin sucursales físicas ni trámites presenciales.
                </p>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 35px;'></div>", unsafe_allow_html=True)

    # CTA Button
    col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
    with col_btn2:
        if st.button("INGRESAR A LA SUCURSAL VIRTUAL"):
            st.session_state.current_page = "app"
            st.rerun()
