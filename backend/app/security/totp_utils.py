"""
Verificación TOTP (RFC 6238) con protección anti-repetición.

Antes: `totp.verify()` aceptaba el mismo código todas las veces que se enviara durante ~30-90 s
(un código interceptado se podía reutilizar: ATT&CK T1111) y no había límite de intentos, así que
las 1 000 000 combinaciones de 6 dígitos eran atacables por fuerza bruta.
Ahora: cada código sólo sirve UNA vez (se guarda el último contador usado) y los fallos se cuentan
para el bloqueo de cuenta (ver accounts.py).
"""
from __future__ import annotations

import hmac
import re
import time

import pyotp

_RE_CODIGO = re.compile(r"^\d{6}$")
_INTERVALO = 30


def _ahora() -> float:      # aislado para poder simular el tiempo en las pruebas
    return time.time()


def generar_secreto() -> str:
    return pyotp.random_base32()


def verificar_codigo(secreto: str, codigo: str, ultimo_contador: int) -> int | None:
    """Devuelve el contador TOTP que coincidió (y es más nuevo que el último usado) o None."""
    codigo = (codigo or "").strip()
    if not _RE_CODIGO.match(codigo):
        return None
    actual = int(_ahora() // _INTERVALO)
    totp = pyotp.TOTP(secreto)
    validos = [
        c for c in (actual - 1, actual, actual + 1)         # tolera ±30 s de desfase de reloj
        if hmac.compare_digest(totp.generate_otp(c), codigo)
    ]
    validos = [c for c in validos if c > ultimo_contador]
    return max(validos) if validos else None
