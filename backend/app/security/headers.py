"""Cabeceras HTTP de seguridad (capa de aplicación). Mitiga sniffing de tipos, clickjacking y caché de datos sensibles."""
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.config import ES_PRODUCCION

_RUTAS_DOCS = ("/docs", "/redoc", "/openapi.json")


class CabecerasSeguridad(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        respuesta = await call_next(request)
        h = respuesta.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cache-Control"] = "no-store"                 # las respuestas contienen tokens / secretos TOTP
        h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if not request.url.path.startswith(_RUTAS_DOCS):  # Swagger necesita scripts; la API no
            h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if ES_PRODUCCION:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return respuesta
