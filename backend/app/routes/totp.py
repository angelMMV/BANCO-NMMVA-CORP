import base64
import io

import qrcode
import pyotp
from fastapi import APIRouter, Depends, Request

from backend.app.database import get_db
from backend.app.models import DatosValidacionTOTP
from backend.app.routes._comun import fallar, ip_cliente
from backend.app.security import accounts
from backend.app.security.audit import registrar_evento
from backend.app.security.crypto import cifrar_campo, descifrar_campo
from backend.app.security.rate_limit import lim_2fa
from backend.app.security.tokens import usuario_enrolamiento
from backend.app.security.totp_utils import generar_secreto, verificar_codigo

router = APIRouter(prefix="/totp", tags=["Seguridad TOTP (2FA)"])


@router.post("/setup", dependencies=[Depends(lim_2fa)])
def setup_totp(request: Request, id_usuario: int = Depends(usuario_enrolamiento), conexion=Depends(get_db)):
    """Enrola 2FA para el usuario DEL TOKEN. Una vez confirmado, el secreto no vuelve a mostrarse."""
    ip = ip_cliente(request)
    cursor = conexion.cursor()
    usuario = accounts.buscar_por_id(cursor, id_usuario)
    if not usuario:
        fallar(conexion, 401, "No autenticado o sesión expirada.")

    if usuario["totp_confirmado"]:
        registrar_evento(cursor, "Re-enrolamiento 2FA rechazado: ya configurado", id_usuario, ip, "WARN")
        fallar(conexion, 409, "El 2FA ya está configurado para esta cuenta.")

    if usuario["totp_secret"]:
        secreto = descifrar_campo(usuario["totp_secret"])
    else:
        secreto = generar_secreto()
        cursor.execute("UPDATE usuarios SET totp_secret = %s WHERE id_usuario = %s",
                       (cifrar_campo(secreto), id_usuario))          # cifrado en reposo
        registrar_evento(cursor, "Enrolamiento de 2FA TOTP iniciado", id_usuario, ip)
    conexion.commit()

    uri = pyotp.TOTP(secreto).provisioning_uri(name=usuario["correo"], issuer_name="NMMVA_CORP")
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer, format="PNG")
    return {
        "status": "Éxito", "id_usuario": id_usuario, "totp_secret": secreto,
        "provisioning_uri": uri, "qr_code_base64": base64.b64encode(buffer.getvalue()).decode("utf-8"),
    }


@router.post("/verify", dependencies=[Depends(lim_2fa)])
def verify_totp(datos: DatosValidacionTOTP, request: Request,
                id_usuario: int = Depends(usuario_enrolamiento), conexion=Depends(get_db)):
    """Confirma el enrolamiento 2FA del usuario del token (con anti-repetición y bloqueo por fallos)."""
    ip = ip_cliente(request)
    cursor = conexion.cursor()
    usuario = accounts.buscar_por_id(cursor, id_usuario)
    if not usuario:
        fallar(conexion, 401, "No autenticado o sesión expirada.")

    if accounts.esta_bloqueado(usuario):
        registrar_evento(cursor, "Verificación TOTP rechazada: cuenta bloqueada", id_usuario, ip, "WARN")
        fallar(conexion, 429, "Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.")
    if not usuario["totp_secret"]:
        fallar(conexion, 400, "El usuario no ha configurado 2FA (TOTP).")

    contador = verificar_codigo(descifrar_campo(usuario["totp_secret"]), datos.totp_code,
                                usuario["ultimo_totp_counter"])
    if contador is None:
        accounts.registrar_fallo(cursor, usuario, ip, "TOTP incorrecto o reutilizado en verificación")
        fallar(conexion, 401, "Código de autenticación 2FA incorrecto, expirado o ya utilizado.")

    accounts.registrar_exito(cursor, id_usuario, contador)
    cursor.execute("UPDATE usuarios SET totp_confirmado = 1 WHERE id_usuario = %s", (id_usuario,))
    registrar_evento(cursor, "Validación 2FA (TOTP) exitosa", id_usuario, ip)
    conexion.commit()
    return {"status": "Éxito", "mensaje": "Autenticación 2FA (TOTP) verificada correctamente."}
