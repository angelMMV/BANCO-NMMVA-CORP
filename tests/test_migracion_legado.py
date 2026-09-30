"""Un proyecto YA en uso (esquema y datos originales) debe migrar sin perder acceso a sus usuarios."""
import hashlib

import pyotp
from fastapi.testclient import TestClient

from backend.app import database
from tests.conftest import conectar, recrear_bd_legada


def test_migracion_de_datos_heredados(bd_disponible):
    recrear_bd_legada()
    secreto_viejo = "JBSWY3DPEHPK3PXP"
    con = conectar(); cur = con.cursor()
    cur.execute("ALTER TABLE usuarios ADD COLUMN totp_secret VARCHAR(32) NULL")   # lo que hacía la app original
    cur.execute("INSERT INTO usuarios (nombre_completo, correo, password_hash, edad, curp, totp_secret) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                ("Luis Viejo", "luis@example.com", hashlib.sha256(b"clave-antigua-1").hexdigest(), 40,
                 "VIEJ800101HDFRRN05", secreto_viejo))
    cur.execute("INSERT INTO contratos_firmados (id_usuario, documento, firma_digital) VALUES (1,'Contrato viejo',%s)",
                (hashlib.sha256(b"firma-heredada").hexdigest(),))
    con.commit()

    from backend.app.main import app
    for _ in range(2):                                           # 2 arranques: la migración es idempotente
        database.reiniciar_estado_esquema()
        with TestClient(app) as client:
            pass

    cur.execute("SELECT curp, totp_secret, totp_confirmado, curp_idx, password_hash FROM usuarios")
    curp, totp, confirmado, idx, pw = cur.fetchone()
    con.commit()
    assert curp.startswith("enc1:") and totp.startswith("enc1:")       # datos en claro ahora cifrados
    assert confirmado == 1 and idx and pw == hashlib.sha256(b"clave-antigua-1").hexdigest()

    database.reiniciar_estado_esquema()
    with TestClient(app) as client:
        # el usuario antiguo inicia sesión con su contraseña ANTIGUA y su mismo TOTP de siempre
        r = client.post("/login", json={"correo": "luis@example.com", "password": "clave-antigua-1",
                                        "totp_code": pyotp.TOTP(secreto_viejo).now()})
        assert r.status_code == 200, r.text
        token = r.json()["token"]
        cur.execute("SELECT password_hash FROM usuarios"); nuevo = cur.fetchone()[0]; con.commit()
        assert nuevo.startswith("scrypt$")                                # se re-hasheó solo
        v = client.post("/verificar-firma", headers={"Authorization": f"Bearer {token}"},
                        json={"firma": hashlib.sha256(b"firma-heredada").hexdigest()})
        assert v.status_code == 200 and v.json()["valida"] is False and "heredada" in v.json()["motivo"]
    cur.close(); con.close()
