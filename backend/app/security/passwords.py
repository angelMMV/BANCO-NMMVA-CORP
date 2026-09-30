"""
Gestión de contraseñas.

Antes: SHA-256 sin sal (rápido y sin sal → crackeable offline con tablas/GPU; ATT&CK T1110.002).
Ahora: scrypt (función memory-hard, con sal aleatoria por usuario) + política de contraseñas
alineada con NIST SP 800-63B (longitud y lista de contraseñas comunes, no reglas de composición).

Compatibilidad: los hashes SHA-256 heredados se siguen aceptando SOLO para iniciar sesión y se
re-hashean con scrypt automáticamente en el primer acceso exitoso (`necesita_actualizacion`).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

_N, _R, _P = 2**15, 8, 3            # parámetros scrypt (OWASP Password Storage Cheat Sheet)
_MAXMEM = 256 * 1024 * 1024
_RE_SHA256_LEGADO = re.compile(r"^[0-9a-f]{64}$")

LARGO_MINIMO = 12
LARGO_MAXIMO = 128                   # tope para evitar DoS por contraseñas gigantes

_COMUNES = {
    "password1234", "password12345", "contrasena123", "contraseña123", "123456789012",
    "1234567890123", "qwertyuiop12", "qwertyuiopas", "administrator", "letmein123456",
    "iloveyou1234", "welcome12345", "changeme1234", "abcdefghijkl", "abc123456789",
    "000000000000", "111111111111", "mexico123456", "bancodigital1", "nmmvacorp123",
}


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def hash_password(password: str) -> str:
    sal = os.urandom(16)
    derivada = hashlib.scrypt(
        password.encode("utf-8"), salt=sal, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32
    )
    return f"scrypt${_N}${_R}${_P}${_b64(sal)}${_b64(derivada)}"


def verificar_password(password: str, almacenado: str) -> bool:
    """Comparación en tiempo constante. Acepta scrypt y el SHA-256 heredado."""
    try:
        if almacenado.startswith("scrypt$"):
            _, n, r, p, sal_b64, hash_b64 = almacenado.split("$")
            esperado = base64.b64decode(hash_b64)
            calculado = hashlib.scrypt(
                password.encode("utf-8"), salt=base64.b64decode(sal_b64),
                n=int(n), r=int(r), p=int(p), maxmem=_MAXMEM, dklen=len(esperado),
            )
            return hmac.compare_digest(calculado, esperado)
        if _RE_SHA256_LEGADO.match(almacenado):
            return hmac.compare_digest(
                hashlib.sha256(password.encode("utf-8")).hexdigest(), almacenado
            )
    except (ValueError, TypeError):
        return False
    return False


def necesita_actualizacion(almacenado: str) -> bool:
    return not almacenado.startswith(f"scrypt${_N}${_R}${_P}$")


_HASH_FALSO: str | None = None


def verificacion_falsa(password: str) -> None:
    """Gasta el mismo tiempo que una verificación real cuando el usuario NO existe,
    para que el tiempo de respuesta no revele qué correos están registrados."""
    global _HASH_FALSO
    if _HASH_FALSO is None:
        _HASH_FALSO = hash_password("contraseña-señuelo-no-valida")
    verificar_password(password, _HASH_FALSO)


def validar_politica(password: str, contexto: list[str] | None = None) -> list[str]:
    """Devuelve la lista de problemas (vacía si la contraseña es aceptable)."""
    problemas: list[str] = []
    if len(password) < LARGO_MINIMO:
        problemas.append(f"debe tener al menos {LARGO_MINIMO} caracteres")
    if len(password) > LARGO_MAXIMO:
        problemas.append(f"no debe exceder {LARGO_MAXIMO} caracteres")
    bajo = password.lower()
    if bajo in _COMUNES or len(set(bajo)) <= 3:
        problemas.append("es demasiado común o repetitiva")
    for dato in contexto or []:
        for trozo in re.split(r"[\s@._-]+", dato.lower()):
            if len(trozo) >= 4 and trozo in bajo:
                problemas.append("no debe contener tu nombre o correo")
                break
    return problemas
