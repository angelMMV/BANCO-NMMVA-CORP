"""
Bitácora de auditoría con cadena de hashes (tamper-evident).

Cada registro incluye HMAC(clave_auditoría, hash_previo + contenido). Si alguien edita, borra o
reordena filas en MySQL sin conocer la clave, la cadena deja de validar en el punto alterado
(`verificar_cadena`). Responde a Repudio/Tampering (STRIDE) y a "Indicator Removal" (T1070).
Además de esta tabla se sigue escribiendo `logs_auditoria` (compatibilidad con reportes previos).
Limitación: el truncado de las últimas filas sólo se detecta si se ancla `ultimo_hash` fuera de la BD.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from backend.app.security.crypto import hmac_auditoria

GENESIS = "0" * 64
_RE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def limpiar(texto: str, maximo: int = 200) -> str:
    """Neutraliza saltos de línea/control (log injection) y acota el tamaño."""
    return _RE_CONTROL.sub(" ", str(texto))[:maximo]


def _contenido(previo, ts, severidad, evento, id_usuario, ip) -> str:
    return json.dumps([previo, ts, severidad, evento, id_usuario, ip],
                      ensure_ascii=True, separators=(",", ":"))


def registrar_evento(cursor, evento: str, id_usuario: int | None = None,
                     ip: str | None = None, severidad: str = "INFO") -> None:
    evento = limpiar(evento, 250)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    # FOR UPDATE serializa a los escritores: la cadena no puede bifurcarse.
    cursor.execute("SELECT hash_evento FROM auditoria_segura ORDER BY id DESC LIMIT 1 FOR UPDATE")
    fila = cursor.fetchone()
    previo = fila[0] if fila else GENESIS
    nuevo = hmac_auditoria(_contenido(previo, ts, severidad, evento, id_usuario, ip))
    cursor.execute(
        "INSERT INTO auditoria_segura (ts_utc, severidad, evento, id_usuario, ip_origen, hash_previo, hash_evento) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (ts, severidad, evento, id_usuario, ip, previo, nuevo),
    )
    cursor.execute("INSERT INTO logs_auditoria (evento, id_usuario) VALUES (%s, %s)", (evento, id_usuario))


def verificar_cadena(cursor) -> dict:
    cursor.execute(
        "SELECT id, ts_utc, severidad, evento, id_usuario, ip_origen, hash_previo, hash_evento "
        "FROM auditoria_segura ORDER BY id ASC"
    )
    previo, total = GENESIS, 0
    while True:
        lote = cursor.fetchmany(500)
        if not lote:
            break
        for (id_, ts, sev, evento, uid, ip, h_prev, h_ev) in lote:
            total += 1
            esperado = hmac_auditoria(_contenido(previo, ts, sev, evento, uid, ip))
            if h_prev != previo or h_ev != esperado:
                return {"integra": False, "registros": total, "primer_registro_alterado": id_, "ultimo_hash": previo}
            previo = h_ev
    return {"integra": True, "registros": total, "primer_registro_alterado": None, "ultimo_hash": previo}
