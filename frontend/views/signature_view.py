import streamlit as st
from frontend.api_client import APIClient

def render_signature_view():
    """Renders digital contract signing view (Step 3)."""
    st.markdown("""
        <div style="margin-bottom: 20px;">
            <h3 style="margin-top:0; color: #FFFFFF;">Paso 3: Firma Criptográfica de Contrato (No Repudio)</h3>
            <p style="color: rgba(255, 255, 255, 0.85); font-size: 0.95rem;">
                Firma legalmente tus contratos bancarios utilizando la combinación de tu Contraseña y tu Código 2FA TOTP.
            </p>
        </div>
    """, unsafe_allow_html=True)

    if not st.session_state.get('id_usuario'):
        st.warning("Primero debes registrar una cuenta de usuario en el Paso 1.")
        return

    with st.form("form_firma"):
        doc = st.text_input("Documento a firmar", value="Contrato de Apertura de Cuenta NMMVA CORP")
        pass_conf = st.text_input("Confirma tu Contraseña", type="password")
        totp_code_sign = st.text_input("Código TOTP de 6 dígitos (App Authenticator)", max_chars=6)

        submitted = st.form_submit_button("GENERAR FIRMA DIGITAL SHA-256")

        if submitted:
            if pass_conf and totp_code_sign:
                try:
                    res = APIClient.firmar_contrato(
                        id_usuario=st.session_state.id_usuario,
                        documento=doc,
                        password_confirmacion=pass_conf,
                        totp_code=totp_code_sign
                    )
                    if res.status_code == 200:
                        data = res.json()
                        st.success("¡Contrato firmado exitosamente!")
                        st.markdown("""
                            <div style="background: rgba(255,255,255,0.08); padding: 15px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.2); margin-top: 10px;">
                                <b>Certificado Digital de No Repudio Emitido:</b><br>
                                <span style="font-size: 0.85rem; color: #E2E8F0;">Hash SHA-256 inmutable registrado en MySQL:</span>
                            </div>
                        """, unsafe_allow_html=True)
                        st.code(data["firma_generada"], language="text")
                    else:
                        st.error(f"Firma Rechazada: {res.json().get('detail', 'Verifica tus datos.')}")
                except Exception as e:
                    st.error(f"Error de conexión con el backend: {e}")
            else:
                st.warning("Por favor ingresa tu contraseña y tu código TOTP de 6 dígitos.")
