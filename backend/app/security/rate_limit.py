"""
Limitador de tasa por IP (ventana deslizante, en memoria).

Mitiga fuerza bruta / password spraying / credential stuffing (ATT&CK T1110.001/.003/.004)
y denegación de servicio en endpoints costosos (T1499): el hash scrypt es deliberadamente caro.
Limitación conocida: es por proceso; con varios workers/servidores usar Redis o el API gateway.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from backend.app.config import LIMITES_ACTIVOS

logger = logging.getLogger("nmmva.ratelimit")
_INSTANCIAS: list["LimitadorPorIP"] = []


class LimitadorPorIP:
    def __init__(self, nombre: str, maximo: int, ventana_s: int):
        self.nombre, self.maximo, self.ventana = nombre, maximo, ventana_s
        self._golpes: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        _INSTANCIAS.append(self)

    def __call__(self, request: Request) -> None:
        if not LIMITES_ACTIVOS:
            return
        ip = request.client.host if request.client else "desconocida"  # no se confía en X-Forwarded-For
        ahora = time.monotonic()
        with self._lock:
            cola = self._golpes[ip]
            while cola and cola[0] <= ahora - self.ventana:
                cola.popleft()
            if len(cola) >= self.maximo:
                espera = max(1, math.ceil(self.ventana - (ahora - cola[0])))
                logger.warning("Límite '%s' excedido por %s", self.nombre, ip)
                raise HTTPException(
                    status_code=429,
                    detail=f"Demasiadas solicitudes. Intenta de nuevo en {espera} s.",
                    headers={"Retry-After": str(espera)},
                )
            cola.append(ahora)
            if len(self._golpes) > 10_000:               # evita crecimiento sin límite de memoria
                for clave in [k for k, v in self._golpes.items() if not v]:
                    del self._golpes[clave]

    def reiniciar(self) -> None:
        with self._lock:
            self._golpes.clear()


def reiniciar_todos() -> None:
    for inst in _INSTANCIAS:
        inst.reiniciar()


lim_registro = LimitadorPorIP("registro", 5, 60)
lim_login = LimitadorPorIP("login", 10, 60)
lim_2fa = LimitadorPorIP("2fa", 15, 60)
lim_firma = LimitadorPorIP("firma", 10, 60)
lim_consulta = LimitadorPorIP("consulta", 20, 60)
