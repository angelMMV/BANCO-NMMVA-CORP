"""
Tokens de sesión (JWT firmado HS256) y control de acceso por alcance (scope).

Antes: el cliente enviaba `id_usuario` en la URL/cuerpo y el servidor le creía → cualquiera podía
hacerse pasar por otro usuario (IDOR / Spoofing) y pedir su secreto TOTP.
Ahora: la identidad sale SIEMPRE del token verificado, nunca de un dato que envíe el cliente.

Alcances:
  * "enroll": lo entrega el registro; sirve únicamente para configurar/confirmar 2FA.
  * "access": lo entrega el login (contraseña + TOTP); necesario para firmar y auditar.
Vida corta (TTL_TOKEN_MIN) para reducir el valor de un token robado (ATT&CK T1528).
"""
from __future__ import annotations

import time
import uuid

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config import TTL_TOKEN_MIN, derivar_clave

EMISOR = "nmmva-corp"
AUDIENCIA = "nmmva-api"
_bearer = HTTPBearer(auto_error=False)


def emitir_token(id_usuario: int, alcance: str, minutos: int = TTL_TOKEN_MIN) -> str:
    ahora = int(time.time())
    claims = {
        "sub": str(id_usuario), "scope": alcance, "iss": EMISOR, "aud": AUDIENCIA,
        "iat": ahora, "exp": ahora + minutos * 60, "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, derivar_clave("jwt-hs256"), algorithm="HS256")


def _no_autorizado() -> HTTPException:
    return HTTPException(
        status_code=401, detail="No autenticado o sesión expirada.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def decodificar_token(token: str, alcances_permitidos: tuple[str, ...]) -> int:
    try:
        claims = jwt.decode(
            token, derivar_clave("jwt-hs256"),
            algorithms=["HS256"],                      # lista fija: evita el ataque "alg=none"
            audience=AUDIENCIA, issuer=EMISOR,
            options={"require": ["exp", "iat", "sub", "scope", "jti"]},
        )
        if claims["scope"] not in alcances_permitidos:
            raise _no_autorizado()
        return int(claims["sub"])
    except (jwt.PyJWTError, ValueError):
        raise _no_autorizado()


def requiere_alcance(*alcances: str):
    def dependencia(cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> int:
        if cred is None or cred.scheme.lower() != "bearer":
            raise _no_autorizado()
        return decodificar_token(cred.credentials, alcances)
    return dependencia


usuario_enrolamiento = requiere_alcance("enroll", "access")
usuario_autenticado = requiere_alcance("access")
