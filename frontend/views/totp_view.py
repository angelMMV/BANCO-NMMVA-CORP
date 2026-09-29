import streamlit as st
import base64
from frontend.api_client import APIClient

def render_totp_view():
    """Renders 2FA TOTP setup and validation view (Step 2)."""
    st.markdown("""
        <div style="margin-bottom: 20px;">
            <h3 style="margin-top:0; color: #FFFFFF;">Paso 2: Configurar Autenticación 2FA (TOTP)</h3>
            <p style="color: rgba(255, 255, 255, 0.85); font-size: 0.95rem;">
                Vincula tu dispositivo móvil con Google Authenticator, Microsoft Authenticator o Authy para proteger cada acceso.
            </p>
        </div>
    """, unsafe_allow_html=True)

    if not st.session_state.get('id_usuario'):
        st.warning("Primero debes registrar una cuenta de usuario en el Paso 1.")
        return

    st.info(f"Configurando Autenticación 2FA para el Usuario ID: {st.session_state.id_usuario}")

    # Sub-section 1: QR Setup
    st.markdown("#### 1. Vincular Dispositivo Authenticator")
    st.caption("Genera y escanea el código QR desde tu aplicación móvil de autenticación.")

    if st.button("GENERAR CÓDIGO QR DE ENROLAMIENTO"):
        try:
            res = APIClient.setup_totp(st.session_state.id_usuario)
            if res.status_code == 200:
                data = res.json()
                qr_bytes = base64.b64decode(data["qr_code_base64"])
                
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.image(qr_bytes, caption="Escanea con tu App", width=220)
                with col2:
                    st.success("¡Código QR generado correctamente!")
                    st.write("Clave secreta para ingreso manual en la app:")
                    st.code(data['totp_secret'], language="text")
            else:
                st.error("Error al obtener la configuración TOTP.")
        except Exception as e:
            st.error(f"Error de conexión con el backend: {e}")

    st.markdown("---")

    # Sub-section 2: Verification
    st.markdown("#### 2. Probar Código TOTP de 6 dígitos")
    codigo_prueba = st.text_input("Ingresa el código de 6 dígitos generado por tu app Authenticator", max_chars=6)

    if st.button("VERIFICAR CÓDIGO 2FA"):
        if codigo_prueba:
            try:
                res = APIClient.verify_totp(st.session_state.id_usuario, codigo_prueba)
                if res.status_code == 200:
                    st.success("¡Código TOTP Válido! Tu dispositivo 2FA ha sido vinculado correctamente.")
                else:
                    st.error(f"{res.json().get('detail', 'Código incorrecto o expirado.')}")
            except Exception as e:
                st.error(f"Error de conexión con el backend: {e}")
        else:
            st.warning("Por favor ingresa un código de 6 dígitos.")
