"""
NMMVA CORP - API bancaria.  Punto de entrada y controles de PERÍMETRO.

Capas aplicadas aquí (Defensa en Profundidad):
  1. TrustedHost: sólo atiende peticiones dirigidas a hosts esperados (mitiga Host-header attacks).
  2. CORS restringido al origen del frontend (antes: "*" con credenciales).
  3. Cabeceras de seguridad HTTP en todas las respuestas.
  4. Errores genéricos hacia el cliente; el detalle técnico queda sólo en el log del servidor.
  5. En producción se deshabilita la documentación interactiva (/docs, /redoc) y /test-db.
"""
import logging
from contextlib import asynccontextmanager

import mysql.connector
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from backend.app import config
from backend.app.database import asegurar_esquema, obtener_conexion
from backend.app.routes import auditoria, auth, signature, totp
from backend.app.security.headers import CabecerasSeguridad

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("nmmva.api")


@asynccontextmanager
async def ciclo_de_vida(_: FastAPI):
    conexion = obtener_conexion()
    if conexion:
        try:
            asegurar_esquema(conexion)
        except Exception:
            logger.exception("Falló la migración del esquema al arrancar")
        finally:
            conexion.close()
    else:
        logger.error("Arranque sin conexión a la BD; se reintentará en la primera petición.")
    yield


app = FastAPI(
    title="NMMVA CORP - Banking API (MFA, firma Ed25519 y auditoría encadenada)",
    description="Registro, 2FA TOTP, login MFA, firma digital con No Repudio y bitácora a prueba de manipulación.",
    lifespan=ciclo_de_vida,
    docs_url=None if config.ES_PRODUCCION else "/docs",
    redoc_url=None if config.ES_PRODUCCION else "/redoc",
    openapi_url=None if config.ES_PRODUCCION else "/openapi.json",
)

app.add_middleware(CabecerasSeguridad)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ORIGENES_PERMITIDOS,
    allow_credentials=False,                       # la API usa Bearer token, no cookies
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.HOSTS_PERMITIDOS)

app.include_router(auth.router)
app.include_router(totp.router)
app.include_router(signature.router)
app.include_router(auditoria.router)


@app.exception_handler(RequestValidationError)
async def validacion_sin_eco(_: Request, exc: RequestValidationError):
    """Responde qué campo falló SIN devolver el valor enviado (Pydantic lo incluiría: p. ej. la contraseña)."""
    partes = []
    for e in exc.errors():
        campo = ".".join(str(x) for x in e["loc"] if x != "body")
        msg = str(e["msg"]).removeprefix("Value error, ")
        partes.append(f"{campo}: {msg}" if campo else msg)
    return JSONResponse(status_code=422, content={"detail": "Datos inválidos — " + "; ".join(partes)})


@app.exception_handler(mysql.connector.Error)
async def error_bd_generico(_: Request, exc: mysql.connector.Error):
    logger.error("Error de base de datos: %s", exc)         # detalle sólo en el servidor
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor."})


@app.get("/", tags=["Health Check"])
def inicio():
    """Health check mínimo (no revela versiones ni configuración)."""
    return {"mensaje": "¡Holi! El backend está corriendo al 100%."}


if not config.ES_PRODUCCION:
    @app.get("/test-db", tags=["Health Check"])
    def probar_bd():
        """Prueba de conexión a la BD (sólo desarrollo; desactivada en producción)."""
        conexion = obtener_conexion()
        if conexion and conexion.is_connected():
            conexion.close()
            return {"status": "Éxito", "mensaje": "¡Conexión a MySQL exitosa!"}
        raise HTTPException(status_code=503, detail="No se pudo conectar a la base de datos.")
