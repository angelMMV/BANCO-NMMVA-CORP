"""Acceso a cuentas y bloqueo por intentos fallidos (mitiga fuerza bruta: ATT&CK T1110)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.app.config import MAX_INTENTOS_FALLIDOS, MINUTOS_BLOQUEO
from backend.app.security.audit import registrar_evento

_COLS = ("id_usuario, correo, password_hash, totp_secret, totp_confirmado, "
         "ultimo_totp_counter, intentos_fallidos, bloqueado_hasta")


def ahora_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _uno(cursor, sql, params):
    cursor.execute(sql, params)
    fila = cursor.fetchone()
    return dict(zip(cursor.column_names, fila)) if fila else None


def buscar_por_id(cursor, id_usuario: int, bloquear: bool = True):
    """`bloquear=True` (SELECT ... FOR UPDATE) serializa intentos concurrentes sobre la misma cuenta,
    de modo que ráfagas paralelas no puedan esquivar el contador de fallos."""
    return _uno(cursor, f"SELECT {_COLS} FROM usuarios WHERE id_usuario = %s" + (" FOR UPDATE" if bloquear else ""),
                (id_usuario,))


def buscar_por_correo(cursor, correo: str, bloquear: bool = True):
    return _uno(cursor, f"SELECT {_COLS} FROM usuarios WHERE correo = %s" + (" FOR UPDATE" if bloquear else ""),
                (correo,))


def esta_bloqueado(usuario: dict) -> bool:
    return bool(usuario["bloqueado_hasta"]) and usuario["bloqueado_hasta"] > ahora_utc()


def registrar_fallo(cursor, usuario: dict, ip: str, motivo: str) -> None:
    intentos = usuario["intentos_fallidos"] + 1
    if intentos >= MAX_INTENTOS_FALLIDOS:
        hasta = ahora_utc() + timedelta(minutes=MINUTOS_BLOQUEO)
        cursor.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = %s WHERE id_usuario = %s",
                       (hasta, usuario["id_usuario"]))
        registrar_evento(cursor, f"Cuenta bloqueada {MINUTOS_BLOQUEO} min por intentos fallidos ({motivo})",
                         usuario["id_usuario"], ip, "ALERTA")
    else:
        cursor.execute("UPDATE usuarios SET intentos_fallidos = %s WHERE id_usuario = %s",
                       (intentos, usuario["id_usuario"]))
        registrar_evento(cursor, f"Intento fallido {intentos}/{MAX_INTENTOS_FALLIDOS}: {motivo}",
                         usuario["id_usuario"], ip, "WARN")


def registrar_exito(cursor, id_usuario: int, contador_totp: int | None = None) -> None:
    if contador_totp is None:
        cursor.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id_usuario = %s",
                       (id_usuario,))
    else:
        cursor.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL, "
                       "ultimo_totp_counter = %s WHERE id_usuario = %s", (contador_totp, id_usuario))
