"""
Acceso a MySQL.

Cambios de seguridad:
  * Credenciales desde variables de entorno (antes: `root` sin contraseña escrito en el código;
    ATT&CK T1552.001 / Privilege Escalation). Ver backend/sql/least_privilege.sql.
  * Timeout de conexión (disponibilidad) y canal cifrado opcional con NMMVA_DB_SSL_CA.
  * Las migraciones ya no corren en CADA petición (antes `ensure_totp_column_exists` hacía DDL
    en cada request): corren una vez por proceso al arrancar (`asegurar_esquema`).
  * Todas las consultas siguen siendo parametrizadas (%s) → mitiga inyección SQL (T1190).
"""
import logging
import threading

import mysql.connector
from fastapi import HTTPException

from backend.app import config

logger = logging.getLogger("nmmva.db")
_esquema_listo = False
_candado = threading.Lock()


def obtener_conexion():
    """Devuelve una conexión MySQL o None si falla (sin filtrar detalles al cliente)."""
    opciones = dict(
        host=config.DB_HOST, port=config.DB_PORT, user=config.DB_USER,
        password=config.DB_PASSWORD, database=config.DB_NAME,
        connection_timeout=5, autocommit=False,
    )
    if config.DB_SSL_CA:
        opciones.update(ssl_ca=config.DB_SSL_CA, ssl_verify_cert=True)
    try:
        return mysql.connector.connect(**opciones)
    except mysql.connector.Error as err:
        logger.error("Conexión a la BD fallida: %s", err)   # el detalle queda en el log del servidor
        return None


def asegurar_esquema(conexion) -> None:
    """Ejecuta las migraciones una sola vez por proceso (idempotentes)."""
    global _esquema_listo
    if _esquema_listo or not config.EJECUTAR_MIGRACIONES:
        return
    with _candado:
        if not _esquema_listo:
            from backend.app.migrations import migrar
            migrar(conexion)
            _esquema_listo = True


def reiniciar_estado_esquema() -> None:
    """Sólo para pruebas."""
    global _esquema_listo
    _esquema_listo = False


def get_db():
    """Dependencia FastAPI: entrega una conexión y garantiza cerrarla (una transacción por petición)."""
    conexion = obtener_conexion()
    if not conexion:
        raise HTTPException(status_code=503, detail="Servicio no disponible temporalmente.")
    try:
        asegurar_esquema(conexion)
        yield conexion
    finally:
        conexion.close()      # lo no confirmado se revierte automáticamente
