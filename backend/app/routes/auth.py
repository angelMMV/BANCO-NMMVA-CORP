from fastapi import APIRouter, Depends, Request
import mysql.connector

from backend.app.database import get_db
from backend.app.models import DatosLogin, UsuarioRegistro
from backend.app.routes._comun import MSG_CREDENCIALES, fallar, ip_cliente
from backend.app.security import accounts
from backend.app.security.audit import registrar_evento
from backend.app.security.crypto import cifrar_campo, indice_ciego
from backend.app.security.passwords import (
    hash_password, necesita_actualizacion, verificacion_falsa, verificar_password,
)
from backend.app.security.crypto import descifrar_campo
from backend.app.security.rate_limit import lim_login, lim_registro
from backend.app.security.tokens import emitir_token
from backend.app.security.totp_utils import verificar_codigo
from backend.app.config import TTL_TOKEN_MIN

router = APIRouter(tags=["Autenticación y Usuarios"])


@router.post("/registro", dependencies=[Depends(lim_registro)])
def registrar_usuario(usuario: UsuarioRegistro, request: Request, conexion=Depends(get_db)):
    """Registra un usuario. Devuelve un token de ENROLAMIENTO (sólo sirve para configurar 2FA)."""
    ip = ip_cliente(request)
    cursor = conexion.cursor()
    try:
        cursor.execute(
            "INSERT INTO usuarios (nombre_completo, correo, password_hash, edad, curp, curp_idx) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (usuario.nombre_completo, usuario.correo, hash_password(usuario.password), usuario.edad,
             cifrar_campo(usuario.curp), indice_ciego(usuario.curp)),
        )
    except mysql.connector.IntegrityError:
        conexion.rollback()
        registrar_evento(cursor, "Registro rechazado: correo o CURP ya registrados", None, ip, "WARN")
        # Mensaje genérico: no confirma cuál de los dos datos existe.
        fallar(conexion, 409, "No fue posible completar el registro con los datos proporcionados.")
    id_nuevo = cursor.lastrowid
    registrar_evento(cursor, "Registro de usuario creado exitosamente", id_nuevo, ip)
    conexion.commit()
    return {
        "status": "Éxito", "mensaje": "Cuenta bancaria creada exitosamente", "id_usuario": id_nuevo,
        "token": emitir_token(id_nuevo, "enroll"), "token_type": "bearer", "expires_in": TTL_TOKEN_MIN * 60,
    }


@router.post("/login", dependencies=[Depends(lim_login)])
def iniciar_sesion(datos: DatosLogin, request: Request, conexion=Depends(get_db)):
    """Autenticación MFA: contraseña + TOTP. Devuelve un token de ACCESO de vida corta."""
    ip = ip_cliente(request)
    cursor = conexion.cursor()
    usuario = accounts.buscar_por_correo(cursor, datos.correo)

    if not usuario:
        verificacion_falsa(datos.password)                      # iguala el tiempo de respuesta
        registrar_evento(cursor, "Login fallido: usuario inexistente", None, ip, "WARN")
        fallar(conexion, 401, MSG_CREDENCIALES)

    if accounts.esta_bloqueado(usuario):
        verificacion_falsa(datos.password)                      # mismo tiempo que un intento normal
        registrar_evento(cursor, "Login rechazado: cuenta bloqueada", usuario["id_usuario"], ip, "WARN")
        fallar(conexion, 401, MSG_CREDENCIALES)

    if not verificar_password(datos.password, usuario["password_hash"]):
        accounts.registrar_fallo(cursor, usuario, ip, "contraseña incorrecta en login")
        fallar(conexion, 401, MSG_CREDENCIALES)

    if not usuario["totp_confirmado"] or not usuario["totp_secret"]:
        registrar_evento(cursor, "Login rechazado: 2FA sin configurar", usuario["id_usuario"], ip, "WARN")
        fallar(conexion, 403, "Debes completar la configuración de 2FA (Paso 2) antes de iniciar sesión.")

    contador = verificar_codigo(descifrar_campo(usuario["totp_secret"]), datos.totp_code,
                                usuario["ultimo_totp_counter"])
    if contador is None:
        accounts.registrar_fallo(cursor, usuario, ip, "TOTP incorrecto o reutilizado en login")
        fallar(conexion, 401, MSG_CREDENCIALES)

    accounts.registrar_exito(cursor, usuario["id_usuario"], contador)
    if necesita_actualizacion(usuario["password_hash"]):        # migra hashes SHA-256 heredados
        cursor.execute("UPDATE usuarios SET password_hash = %s WHERE id_usuario = %s",
                       (hash_password(datos.password), usuario["id_usuario"]))
        registrar_evento(cursor, "Hash de contraseña actualizado a scrypt", usuario["id_usuario"], ip)
    registrar_evento(cursor, "Login exitoso (contraseña + TOTP)", usuario["id_usuario"], ip)
    conexion.commit()
    return {"status": "Éxito", "id_usuario": usuario["id_usuario"],
            "token": emitir_token(usuario["id_usuario"], "access"),
            "token_type": "bearer", "expires_in": TTL_TOKEN_MIN * 60}
