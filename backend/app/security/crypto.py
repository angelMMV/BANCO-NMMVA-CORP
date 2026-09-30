"""
Primitivas criptográficas de la aplicación.

  * Cifrado de campos sensibles en reposo (Fernet = AES-128-CBC + HMAC-SHA256, autenticado).
    Se usa para el secreto TOTP y la CURP (PII).                       → Confidencialidad (X.800 4.3)
  * Índice ciego (HMAC) para poder buscar/deduplicar CURP sin guardarla en claro.
  * Firma digital Ed25519 del servidor sobre un mensaje canónico.       → Integridad / No repudio
  * HMAC para encadenar la bitácora de auditoría.                       → Integridad (X.800 4.4)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from backend.app.config import derivar_clave

PREFIJO_CIFRADO = "enc1:"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derivar_clave("campos-fernet")))


def esta_cifrado(valor: str) -> bool:
    return valor.startswith(PREFIJO_CIFRADO)


def cifrar_campo(texto: str) -> str:
    return PREFIJO_CIFRADO + _fernet().encrypt(texto.encode("utf-8")).decode("ascii")


def descifrar_campo(valor: str) -> str:
    """Descifra. Si el valor no lleva prefijo es un dato heredado en claro y se devuelve tal cual
    (la migración lo cifra una sola vez al arrancar)."""
    if not esta_cifrado(valor):
        return valor
    try:
        return _fernet().decrypt(valor[len(PREFIJO_CIFRADO):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("No se pudo descifrar el campo: clave incorrecta o dato alterado.") from exc


def indice_ciego(texto: str) -> str:
    return hmac.new(derivar_clave("indice-ciego"), texto.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_auditoria(texto: str) -> str:
    return hmac.new(derivar_clave("auditoria-hmac"), texto.encode("utf-8"), hashlib.sha256).hexdigest()


@lru_cache(maxsize=1)
def _clave_firma() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(derivar_clave("firma-ed25519"))


def clave_publica_hex() -> str:
    return _clave_firma().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def firmar(mensaje: bytes) -> str:
    return _clave_firma().sign(mensaje).hex()


def verificar_firma(mensaje: bytes, firma_hex: str) -> bool:
    try:
        _clave_firma().public_key().verify(bytes.fromhex(firma_hex), mensaje)
        return True
    except (InvalidSignature, ValueError):
        return False
