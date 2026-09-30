import streamlit as st
from frontend.api_client import APIClient


def _render_login():
    st.markdown("#### Inicia sesión (contraseña + código 2FA)")
    st.caption("Autenticación multifactor: algo que sabes (contraseña) y algo que tienes (tu app Authenticator).")
    with st.form("form_login"):
        correo = st.text_input("Correo Electrónico", max_chars=100)
        password = st.text_input("Contraseña", type="password", max_chars=128)
        codigo = st.text_input("Código TOTP de 6 dígitos", max_chars=6)
        if st.form_submit_button("INICIAR SESIÓN"):
            if correo and password and codigo:
                try:
                    res = APIClient.login(correo, password, codigo)
                    if res.status_code == 200:
                        datos = res.json()
                        st.session_state.token_access = datos["token"]
                        st.session_state.id_usuario = datos["id_usuario"]
                        st.rerun()
                    else:
                        st.error(APIClient.mensaje_error(res, "No se pudo iniciar sesión."))
                except Exception:
                    st.error("Error de conexión con el backend.")
            else:
                st.warning("Completa correo, contraseña y código TOTP.")


def render_signature_view():
    """Renders digital contract signing view (Step 3)."""
    st.markdown("""
        <div style="margin-bottom: 20px;">
            <h3 style="margin-top:0; color: #FFFFFF;">Paso 3: Firma Criptográfica de Contrato (No Repudio)</h3>
            <p style="color: rgba(255, 255, 255, 0.85); font-size: 0.95rem;">
                Firma tus contratos bancarios: sesión MFA + contraseña + un código 2FA nuevo. La firma es Ed25519 y queda ligada al documento, a tu usuario y a la fecha.
            </p>
        </div>
    """, unsafe_allow_html=True)

    token = st.session_state.get('token_access')
    if not token:
        _render_login()
        return

    st.caption("Los códigos TOTP son de un solo uso: si acabas de iniciar sesión, espera a que tu app muestre un código nuevo.")
    with st.form("form_firma"):
        doc = st.text_input("Documento a firmar", value="Contrato de Apertura de Cuenta NMMVA CORP", max_chars=255)
        pass_conf = st.text_input("Confirma tu Contraseña", type="password", max_chars=128)
        totp_code_sign = st.text_input("Código TOTP de 6 dígitos (App Authenticator)", max_chars=6)

        submitted = st.form_submit_button("GENERAR FIRMA DIGITAL ED25519")

        if submitted:
            if pass_conf and totp_code_sign:
                try:
                    res = APIClient.firmar_contrato(token, doc, pass_conf, totp_code_sign)
                    if res.status_code == 200:
                        data = res.json()
                        st.success("¡Contrato firmado exitosamente!")
                        st.markdown("""
                            <div style="background: rgba(255,255,255,0.08); padding: 15px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.2); margin-top: 10px;">
                                <b>Certificado Digital de No Repudio Emitido:</b><br>
                                <span style="font-size: 0.85rem; color: #E2E8F0;">Firma Ed25519 registrada en MySQL (ligada al hash SHA-256 del documento):</span>
                            </div>
                        """, unsafe_allow_html=True)
                        st.code(data["firma_generada"], language="text")
                        st.caption(f"SHA-256 del documento: {data['documento_sha256']}  |  UTC: {data['firmado_en_utc']}")
                        chk = APIClient.verificar_firma(token, data["firma_generada"])
                        if chk.status_code == 200 and chk.json().get("valida"):
                            st.success("Verificación independiente: firma auténtica y documento íntegro.")
                    elif res.status_code == 401 and "sesión" in APIClient.mensaje_error(res).lower():
                        st.session_state.token_access = None
                        st.warning("Tu sesión expiró. Inicia sesión de nuevo.")
                        st.rerun()
                    else:
                        st.error(APIClient.mensaje_error(res, "Firma rechazada: verifica tus datos."))
                except Exception:
                    st.error("Error de conexión con el backend.")
            else:
                st.warning("Por favor ingresa tu contraseña y tu código TOTP de 6 dígitos.")
