"""
Configuración de pruebas. Usa una base SEPARADA (nmmva_bank_test): nunca toca tus datos reales.
Las pruebas de integración se omiten solas si no hay MySQL/MariaDB accesible con root sin contraseña
(configurable con TEST_DB_USER / TEST_DB_PASSWORD).
"""
import os
import time

# --- deben fijarse ANTES de importar la app ---
os.environ.setdefault("NMMVA_DB_NAME", "nmmva_bank_test")
os.environ.setdefault("NMMVA_ALLOWED_HOSTS", "testserver,localhost")
os.environ.setdefault("NMMVA_ENV", "development")

import mysql.connector
import pyotp
import pytest

from backend.app import config, database
from backend.app.security import rate_limit, totp_utils

_USER = os.getenv("TEST_DB_USER", "root")
_PASS = os.getenv("TEST_DB_PASSWORD", "")
_HOST = os.getenv("TEST_DB_HOST", "localhost")

ESQUEMA_LEGADO = [
    """CREATE TABLE usuarios (id_usuario INT AUTO_INCREMENT PRIMARY KEY, nombre_completo VARCHAR(100) NOT NULL,
       correo VARCHAR(100) NOT NULL UNIQUE, password_hash VARCHAR(64) NOT NULL, edad INT NOT NULL,
       curp VARCHAR(18) NOT NULL UNIQUE)""",
    """CREATE TABLE logs_auditoria (id_log INT AUTO_INCREMENT PRIMARY KEY, evento VARCHAR(255) NOT NULL,
       id_usuario INT NULL, fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE contratos_firmados (id_contrato INT AUTO_INCREMENT PRIMARY KEY, id_usuario INT NOT NULL,
       documento VARCHAR(255) NOT NULL, firma_digital VARCHAR(64) NOT NULL,
       fecha_firma TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
]


def conectar(sin_bd=False):
    args = dict(host=_HOST, user=_USER, password=_PASS)
    if not sin_bd:
        args["database"] = config.DB_NAME
    return mysql.connector.connect(**args)


def recrear_bd_legada():
    c = conectar(sin_bd=True)
    cur = c.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS {config.DB_NAME}")
    cur.execute(f"CREATE DATABASE {config.DB_NAME}")
    cur.execute(f"USE {config.DB_NAME}")
    for ddl in ESQUEMA_LEGADO:
        cur.execute(ddl)
    c.commit(); cur.close(); c.close()


@pytest.fixture(scope="session")
def bd_disponible():
    try:
        recrear_bd_legada()
    except mysql.connector.Error as e:
        pytest.skip(f"MySQL/MariaDB no disponible para pruebas de integración: {e}")


@pytest.fixture(autouse=True)
def _limites_limpios():
    rate_limit.reiniciar_todos()
    yield


@pytest.fixture
def reloj(monkeypatch):
    """Reloj falso para TOTP: cada `avanzar()` salta al siguiente intervalo de 30 s."""
    estado = {"t": float(int(time.time() // 30) * 30 + 5)}
    monkeypatch.setattr(totp_utils, "_ahora", lambda: estado["t"])

    class Reloj:
        def codigo(self, secreto: str) -> str:
            return pyotp.TOTP(secreto).at(estado["t"])

        def avanzar(self, pasos: int = 1):
            estado["t"] += 30 * pasos
    return Reloj()


@pytest.fixture
def client(bd_disponible):
    from fastapi.testclient import TestClient
    from backend.app.main import app
    database.reiniciar_estado_esquema()
    with TestClient(app) as c:
        con = conectar(); cur = con.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for t in ("usuarios", "logs_auditoria", "contratos_firmados", "auditoria_segura"):
            cur.execute(f"TRUNCATE TABLE {t}")
        con.commit(); cur.close(); con.close()
        yield c


@pytest.fixture
def sql():
    """Ejecuta SQL directo (para inspeccionar/alterar la BD como lo haría un atacante con acceso a MySQL)."""
    def _run(consulta, params=()):
        con = conectar(); cur = con.cursor()
        cur.execute(consulta, params)
        filas = cur.fetchall() if cur.description else None
        con.commit(); cur.close(); con.close()
        return filas
    return _run
