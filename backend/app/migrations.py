"""
Migraciones idempotentes del esquema de seguridad.

Parten del esquema original (usuarios / logs_auditoria / contratos_firmados) y:
  * amplían columnas (hash, secreto TOTP cifrado, CURP cifrada, firma Ed25519),
  * agregan las columnas de 2FA reforzado y bloqueo de cuenta,
  * crean `auditoria_segura` (bitácora encadenada),
  * cifran una única vez los datos heredados que estaban en claro (TOTP y CURP).
"""
import logging

import mysql.connector

from backend.app import config
from backend.app.security.crypto import cifrar_campo, esta_cifrado, indice_ciego, descifrar_campo

logger = logging.getLogger("nmmva.migrations")


def _existe_col(cur, tabla, col) -> bool:
    cur.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s", (config.DB_NAME, tabla, col))
    return cur.fetchone()[0] > 0


def _agregar_col(cur, tabla, col, ddl) -> bool:
    if _existe_col(cur, tabla, col):
        return False
    cur.execute(f"ALTER TABLE {tabla} ADD COLUMN {col} {ddl}")
    logger.info("Migración: %s.%s agregada", tabla, col)
    return True


def _ampliar_varchar(cur, tabla, col, largo, definicion_nula):
    cur.execute("SELECT CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s", (config.DB_NAME, tabla, col))
    fila = cur.fetchone()
    if fila and fila[0] is not None and fila[0] < largo:
        cur.execute(f"ALTER TABLE {tabla} MODIFY COLUMN {col} VARCHAR({largo}) {definicion_nula}")
        logger.info("Migración: %s.%s ampliada a VARCHAR(%s)", tabla, col, largo)


def _agregar_indice_unico(cur, tabla, nombre, col):
    cur.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS "
                "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND INDEX_NAME=%s", (config.DB_NAME, tabla, nombre))
    if cur.fetchone()[0] == 0:
        try:
            cur.execute(f"ALTER TABLE {tabla} ADD UNIQUE INDEX {nombre} ({col})")
        except mysql.connector.Error as err:      # p. ej. ya existen duplicados: se avisa, no se rompe
            logger.warning("No se pudo crear el índice único %s: %s", nombre, err)


def migrar(conexion) -> None:
    cur = conexion.cursor()
    try:
        # ---- usuarios ----
        _ampliar_varchar(cur, "usuarios", "password_hash", 255, "NOT NULL")
        _ampliar_varchar(cur, "usuarios", "curp", 255, "NOT NULL")
        if not _existe_col(cur, "usuarios", "totp_secret"):
            cur.execute("ALTER TABLE usuarios ADD COLUMN totp_secret VARCHAR(255) NULL")
        _ampliar_varchar(cur, "usuarios", "totp_secret", 255, "NULL")
        confirmado_nuevo = _agregar_col(cur, "usuarios", "totp_confirmado", "TINYINT(1) NOT NULL DEFAULT 0")
        if confirmado_nuevo:   # usuarios previos que ya usaban su TOTP: se consideran confirmados
            cur.execute("UPDATE usuarios SET totp_confirmado = 1 WHERE totp_secret IS NOT NULL")
        _agregar_col(cur, "usuarios", "ultimo_totp_counter", "BIGINT NOT NULL DEFAULT 0")
        _agregar_col(cur, "usuarios", "intentos_fallidos", "INT NOT NULL DEFAULT 0")
        _agregar_col(cur, "usuarios", "bloqueado_hasta", "DATETIME NULL")
        _agregar_col(cur, "usuarios", "curp_idx", "CHAR(64) NULL")
        _agregar_indice_unico(cur, "usuarios", "uq_usuarios_curp_idx", "curp_idx")

        # ---- cifrado único de datos heredados en claro ----
        cur.execute("SELECT id_usuario, totp_secret, curp, curp_idx FROM usuarios")
        for id_usuario, totp, curp, curp_idx in cur.fetchall():
            cambios, valores = [], []
            if totp and not esta_cifrado(totp):
                cambios.append("totp_secret = %s"); valores.append(cifrar_campo(totp))
            if curp and not esta_cifrado(curp):
                cambios.append("curp = %s"); valores.append(cifrar_campo(curp))
            if curp and not curp_idx:
                claro = descifrar_campo(curp) if esta_cifrado(curp) else curp
                cambios.append("curp_idx = %s"); valores.append(indice_ciego(claro.upper()))
            if cambios:
                cur.execute(f"UPDATE usuarios SET {', '.join(cambios)} WHERE id_usuario = %s", (*valores, id_usuario))

        # ---- contratos_firmados ----
        _ampliar_varchar(cur, "contratos_firmados", "firma_digital", 255, "NOT NULL")
        _agregar_col(cur, "contratos_firmados", "algoritmo", "VARCHAR(20) NULL")
        _agregar_col(cur, "contratos_firmados", "documento_sha256", "CHAR(64) NULL")
        _agregar_col(cur, "contratos_firmados", "firmado_en_utc", "VARCHAR(32) NULL")
        _agregar_col(cur, "contratos_firmados", "mensaje_firmado", "TEXT NULL")

        # ---- bitácora encadenada ----
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auditoria_segura (
                id          BIGINT AUTO_INCREMENT PRIMARY KEY,
                ts_utc      VARCHAR(32)  NOT NULL,
                severidad   VARCHAR(10)  NOT NULL,
                evento      VARCHAR(255) NOT NULL,
                id_usuario  INT NULL,
                ip_origen   VARCHAR(45)  NULL,
                hash_previo CHAR(64)     NOT NULL,
                hash_evento CHAR(64)     NOT NULL
            )
        """)
        conexion.commit()
    except Exception:
        conexion.rollback()
        raise
    finally:
        cur.close()


if __name__ == "__main__":
    # Uso en producción:  NMMVA_DB_USER=nmmva_migrator ... python -m backend.app.migrations
    from backend.app.database import obtener_conexion
    logging.basicConfig(level=logging.INFO)
    conexion = obtener_conexion()
    if not conexion:
        raise SystemExit("No se pudo conectar a la base de datos.")
    migrar(conexion)
    conexion.close()
    print("Migraciones aplicadas.")
