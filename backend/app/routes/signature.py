import json
import secrets
from datetime import datetime, timezone
import hashlib

from fastapi import APIRouter, Depends, Request

from backend.app.database import get_db
from backend.app.models import DatosFirma, DatosVerificarFirma
from backend.app.routes._comun import MSG_CREDENCIALES, fallar, ip_cliente
from backend.app.security import accounts
from backend.app.security.audit import limpiar, registrar_evento
from backend.app.security.crypto import (
    clave_publica_hex, descifrar_campo, firmar, verificar_firma,
)
from backend.app.security.passwords import verificar_password
from backend.app.security.rate_limit import lim_consulta, lim_firma
from backend.app.security.tokens import usuario_autenticado
from backend.app.security.totp_utils import verificar_codigo

router = APIRouter(tags=["Firma Digital Criptográfica"])


def _mensaje_canonico(id_usuario: int, doc_sha256: str, ts: str, nonce: str) -> str:
    return json.dumps({"alg": "Ed25519", "doc_sha256": doc_sha256, "nonce": nonce, "ts": ts,
                       "user": id_usuario, "v": 1}, sort_keys=True, separators=(",", ":"))


@router.post("/firmar-contrato", dependencies=[Depends(lim_firma)])
def firmar_contrato(datos: DatosFirma, request: Request,
                    id_usuario: int = Depends(usuario_autenticado), conexion=Depends(get_db)):
    """
    Firma un contrato. Requiere: sesión (token de acceso) + contraseña + TOTP nuevo (autenticación reforzada
    por operación). La firma es Ed25519 del servidor sobre {hash del documento, usuario, fecha UTC, nonce}.
    """
    ip = ip_cliente(request)
    cursor = conexion.cursor()
    usuario = accounts.buscar_por_id(cursor, id_usuario)
    if not usuario:
        fallar(conexion, 401, "No autenticado o sesión expirada.")
    if accounts.esta_bloqueado(usuario):
        registrar_evento(cursor, "Firma rechazada: cuenta bloqueada", id_usuario, ip, "WARN")
        fallar(conexion, 429, "Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.")

    if not verificar_password(datos.password_confirmacion, usuario["password_hash"]):
        accounts.registrar_fallo(cursor, usuario, ip, "contraseña incorrecta al firmar")
        fallar(conexion, 401, "Firma rechazada: verificación de identidad fallida.")
    if not usuario["totp_confirmado"] or not usuario["totp_secret"]:
        fallar(conexion, 400, "Firma rechazada: debes configurar 2FA (TOTP) antes de firmar.")

    contador = verificar_codigo(descifrar_campo(usuario["totp_secret"]), datos.totp_code,
                                usuario["ultimo_totp_counter"])
    if contador is None:
        accounts.registrar_fallo(cursor, usuario, ip, "TOTP incorrecto o reutilizado al firmar")
        fallar(conexion, 401, "Firma rechazada: verificación de identidad fallida "
                              "(el código TOTP es de un solo uso; espera al siguiente).")

    accounts.registrar_exito(cursor, id_usuario, contador)
    doc_sha256 = hashlib.sha256(datos.documento.encode("utf-8")).hexdigest()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    mensaje = _mensaje_canonico(id_usuario, doc_sha256, ts, secrets.token_hex(16))
    firma = firmar(mensaje.encode("utf-8"))

    cursor.execute(
        "INSERT INTO contratos_firmados (id_usuario, documento, firma_digital, algoritmo, "
        "documento_sha256, firmado_en_utc, mensaje_firmado) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (id_usuario, datos.documento, firma, "Ed25519", doc_sha256, ts, mensaje),
    )
    registrar_evento(cursor, f"Contrato firmado (Ed25519, sha256={doc_sha256[:16]}…): {limpiar(datos.documento, 80)}",
                     id_usuario, ip)
    conexion.commit()
    return {
        "status": "Éxito",
        "mensaje": "Contrato firmado con éxito. Autenticación multifactor y evidencia de No Repudio registradas.",
        "firma_generada": firma, "algoritmo": "Ed25519", "documento_sha256": doc_sha256,
        "firmado_en_utc": ts, "clave_publica": clave_publica_hex(),
    }


@router.post("/verificar-firma", dependencies=[Depends(lim_consulta)])
def verificar_firma_contrato(datos: DatosVerificarFirma, request: Request,
                             id_usuario: int = Depends(usuario_autenticado), conexion=Depends(get_db)):
    """Comprueba que una firma es auténtica y que el documento guardado no fue alterado. Sólo el dueño puede consultarla."""
    cursor = conexion.cursor()
    cursor.execute("SELECT documento, mensaje_firmado FROM contratos_firmados WHERE firma_digital = %s AND id_usuario = %s",
                   (datos.firma, id_usuario))
    fila = cursor.fetchone()
    if not fila:
        fallar(conexion, 404, "Firma no encontrada.")
    documento, mensaje = fila
    if not mensaje:
        return {"valida": False, "motivo": "Firma heredada (SHA-256 sin clave): no es verificable criptográficamente."}
    firma_ok = verificar_firma(mensaje.encode("utf-8"), datos.firma)
    doc_ok = json.loads(mensaje)["doc_sha256"] == hashlib.sha256(documento.encode("utf-8")).hexdigest()
    return {"valida": firma_ok and doc_ok, "firma_autentica": firma_ok, "documento_integro": doc_ok}
