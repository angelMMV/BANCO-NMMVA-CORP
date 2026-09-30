import base64

import streamlit as st
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

    token = st.session_state.get('token_enroll') or st.session_state.get('token_access')
    if not st.session_state.get('id_usuario') or not token:
        st.warning("Primero debes registrar una cuenta de usuario en el Paso 1.")
        return

    st.info(f"Configurando Autenticación 2FA para el Usuario ID: {st.session_state.id_usuario}")

    # Sub-section 1: QR Setup
    st.markdown("#### 1. Vincular Dispositivo Authenticator")
    st.caption("Genera y escanea el código QR desde tu aplicación móvil de autenticación. "
               "El secreto solo se muestra durante el enrolamiento; una vez confirmado no vuelve a mostrarse.")

    if st.button("GENERAR CÓDIGO QR DE ENROLAMIENTO"):
        try:
            res = APIClient.setup_totp(token)
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
            elif res.status_code == 409:
                st.info("Tu 2FA ya está configurado. Ve al Paso 3 para iniciar sesión.")
            else:
                st.error(APIClient.mensaje_error(res, "Error al obtener la configuración TOTP."))
        except Exception:
            st.error("Error de conexión con el backend.")

    st.markdown("---")

    # Sub-section 2: Verification
    st.markdown("#### 2. Confirmar Código TOTP de 6 dígitos")
    codigo_prueba = st.text_input("Ingresa el código de 6 dígitos generado por tu app Authenticator", max_chars=6)

    if st.button("VERIFICAR CÓDIGO 2FA"):
        if codigo_prueba:
            try:
                res = APIClient.verify_totp(token, codigo_prueba)
                if res.status_code == 200:
                    st.success("¡Código TOTP válido! Tu dispositivo 2FA ha sido vinculado. "
                               "Ahora inicia sesión en el Paso 3.")
                else:
                    st.error(APIClient.mensaje_error(res, "Código incorrecto o expirado."))
            except Exception:
                st.error("Error de conexión con el backend.")
        else:
            st.warning("Por favor ingresa un código de 6 dígitos.")
