import streamlit as st
from frontend.api_client import APIClient


def render_registration_view():
    """Renders user account creation view (Step 1)."""
    st.markdown("""
        <div style="margin-bottom: 20px;">
            <h3 style="margin-top:0; color: #FFFFFF;">Paso 1: Crear Cuenta (Trazabilidad)</h3>
            <p style="color: rgba(255, 255, 255, 0.85); font-size: 0.95rem;">
                Ingresa tus datos personales para aperturar tu cuenta bancaria digital y registrar la auditoría inmutable en el sistema.
            </p>
        </div>
    """, unsafe_allow_html=True)

    with st.form("form_registro", clear_on_submit=False):
        col1, col2 = st.columns(2)
        with col1:
            nombre = st.text_input("Nombre Completo", max_chars=100)
            correo = st.text_input("Correo Electrónico", max_chars=100)
            edad = st.number_input("Edad", min_value=18, max_value=100, step=1, value=25)
        with col2:
            password = st.text_input("Contraseña", type="password", max_chars=128,
                                     help="Mínimo 12 caracteres. Usa una frase larga; evita tu nombre, tu correo o contraseñas comunes.")
            curp = st.text_input("CURP", max_chars=18)

        submitted = st.form_submit_button("REGISTRAR CUENTA BANCARIA")

        if submitted:
            if nombre and correo and password and curp:
                try:
                    res = APIClient.registrar_usuario(nombre, correo, password, edad, curp)
                    if res.status_code == 200:
                        datos = res.json()
                        st.session_state.id_usuario = datos["id_usuario"]
                        st.session_state.token_enroll = datos["token"]
                        st.session_state.token_access = None
                        st.success(f"¡Cuenta creada con éxito! Tu ID de Usuario es: {datos['id_usuario']}")
                        st.info("Pasa al Paso 2 en la pestaña superior para configurar tu doble factor (2FA TOTP).")
                    else:
                        st.error(f"No se pudo registrar: {APIClient.mensaje_error(res)}")
                except Exception:
                    st.error("No se pudo conectar con el Backend. Verifica que esté en ejecución.")
            else:
                st.warning("Por favor llena todos los campos del formulario.")
