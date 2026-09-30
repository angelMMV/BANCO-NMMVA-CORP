"""
Configuración central de seguridad de NMMVA CORP.

Principios aplicados (Defensa en Profundidad / ATT&CK T1552.001):
  * Ningún secreto vive en el código fuente. Todo sale de variables de entorno.
  * UNA sola clave maestra (NMMVA_MASTER_KEY) de la que se DERIVAN, con HKDF,
    claves independientes por propósito (JWT, cifrado de campos, firma, auditoría).
    Así, comprometer una clave derivada no compromete las demás.
  * En desarrollo se genera una clave local en `.secrets/` (ignorada por git).
    En producción (NMMVA_ENV=production) la app NO arranca si falta un secreto.
"""
from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger("nmmva.config")

ENTORNO = os.getenv("NMMVA_ENV", "development").strip().lower()
ES_PRODUCCION = ENTORNO == "production"


def _env(nombre: str, defecto: str | None = None, *, obligatorio_en_prod: bool = False) -> str:
    valor = os.getenv(nombre)
    if valor is None or valor == "":
        if ES_PRODUCCION and obligatorio_en_prod:
            raise RuntimeError(f"Variable de entorno obligatoria en producción: {nombre}")
        return defecto if defecto is not None else ""
    return valor


# ── Base de datos (usuario de mínimo privilegio; ver backend/sql/least_privilege.sql) ──
DB_HOST = _env("NMMVA_DB_HOST", "localhost")
DB_PORT = int(_env("NMMVA_DB_PORT", "3306"))
DB_USER = _env("NMMVA_DB_USER", "root", obligatorio_en_prod=True)
DB_PASSWORD = _env("NMMVA_DB_PASSWORD", "", obligatorio_en_prod=True)
DB_NAME = _env("NMMVA_DB_NAME", "nmmva_bank")
DB_SSL_CA = _env("NMMVA_DB_SSL_CA", "")  # ruta al CA para cifrar el canal app<->MySQL

if ES_PRODUCCION and (DB_USER == "root" or not DB_PASSWORD):
    raise RuntimeError("Producción prohíbe usar 'root' o una contraseña de BD vacía.")

# ── Perímetro ──
ORIGENES_PERMITIDOS = [
    o.strip()
    for o in _env("NMMVA_CORS_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501").split(",")
    if o.strip()
]
HOSTS_PERMITIDOS = [
    h.strip() for h in _env("NMMVA_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()
]
LIMITES_ACTIVOS = _env("NMMVA_RATE_LIMIT", "on").lower() != "off"
# En producción las migraciones (DDL) se corren aparte con la cuenta migrator: python -m backend.app.migrations
EJECUTAR_MIGRACIONES = _env("NMMVA_RUN_MIGRATIONS", "off" if ES_PRODUCCION else "on").lower() == "on"

# ── Políticas de autenticación ──
TTL_TOKEN_MIN = int(_env("NMMVA_TOKEN_TTL_MIN", "15"))       # sesión corta (menor ventana de robo)
MAX_INTENTOS_FALLIDOS = int(_env("NMMVA_MAX_FAILED", "5"))   # bloqueo de cuenta (T1110)
MINUTOS_BLOQUEO = int(_env("NMMVA_LOCK_MIN", "15"))

# ── Gestión de claves ──
_RUTA_CLAVE_DEV = Path(__file__).resolve().parents[2] / ".secrets" / "master.key"


@lru_cache(maxsize=1)
def _clave_maestra() -> bytes:
    valor = os.getenv("NMMVA_MASTER_KEY", "")
    if valor:
        if len(valor) < 32:
            raise RuntimeError("NMMVA_MASTER_KEY debe tener al menos 32 caracteres.")
        return valor.encode()
    if ES_PRODUCCION:
        raise RuntimeError("Producción requiere NMMVA_MASTER_KEY (no se autogeneran claves).")
    if _RUTA_CLAVE_DEV.exists():
        return _RUTA_CLAVE_DEV.read_text().strip().encode()
    _RUTA_CLAVE_DEV.parent.mkdir(parents=True, exist_ok=True)
    nueva = secrets.token_urlsafe(48)
    _RUTA_CLAVE_DEV.write_text(nueva)
    try:
        os.chmod(_RUTA_CLAVE_DEV, 0o600)
    except OSError:
        pass
    logger.warning(
        "Clave maestra de DESARROLLO generada en %s. No la subas a git ni la pierdas: "
        "los datos cifrados con ella no se pueden recuperar.", _RUTA_CLAVE_DEV,
    )
    return nueva.encode()


@lru_cache(maxsize=None)
def derivar_clave(proposito: str) -> bytes:
    """Deriva una clave de 32 bytes específica para `proposito` (separación de claves)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=f"nmmva-corp/{proposito}".encode()
    ).derive(_clave_maestra())
