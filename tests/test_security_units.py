"""Pruebas unitarias de los controles (no requieren base de datos)."""
import time

import jwt
import pytest
from fastapi import HTTPException

from backend.app.security import crypto, passwords, rate_limit, tokens, totp_utils
import hashlib
import pyotp


# ---------- Contraseñas ----------
def test_scrypt_con_sal_unica():
    a, b = passwords.hash_password("Una-contraseña-larga-1"), passwords.hash_password("Una-contraseña-larga-1")
    assert a != b and a.startswith("scrypt$")            # misma clave -> hashes distintos (sal)
    assert passwords.verificar_password("Una-contraseña-larga-1", a)
    assert not passwords.verificar_password("otra", a)


def test_hash_sha256_legado_se_acepta_y_marca_para_actualizar():
    legado = hashlib.sha256(b"vieja-clave").hexdigest()
    assert passwords.verificar_password("vieja-clave", legado)
    assert passwords.necesita_actualizacion(legado)
    assert not passwords.necesita_actualizacion(passwords.hash_password("x" * 12))


@pytest.mark.parametrize("pw", ["corta", "password1234", "aaaaaaaaaaaa", "x" * 200])
def test_politica_rechaza_contraseñas_debiles(pw):
    assert passwords.validar_politica(pw)


def test_politica_rechaza_nombre_o_correo_dentro_de_la_contraseña():
    assert passwords.validar_politica("angelmartinez2026!", ["Angel Martinez", "a@x.com"])
    assert not passwords.validar_politica("Caballo-Grapa-Nube-77", ["Angel Martinez"])


# ---------- Criptografía ----------
def test_cifrado_de_campos_ida_y_vuelta_y_deteccion_de_alteracion():
    c = crypto.cifrar_campo("JBSWY3DPEHPK3PXP")
    assert c.startswith("enc1:") and "JBSWY3" not in c
    assert crypto.descifrar_campo(c) == "JBSWY3DPEHPK3PXP"
    assert crypto.descifrar_campo("dato-heredado-en-claro") == "dato-heredado-en-claro"
    with pytest.raises(RuntimeError):
        crypto.descifrar_campo(c[:-4] + "AAAA")           # ciphertext alterado -> falla, no devuelve basura


def test_firma_ed25519_detecta_cualquier_cambio():
    msg = b'{"doc":"abc","user":1}'
    firma = crypto.firmar(msg)
    assert len(firma) == 128 and crypto.verificar_firma(msg, firma)
    assert not crypto.verificar_firma(msg + b" ", firma)
    assert not crypto.verificar_firma(msg, "00" * 64)
    assert not crypto.verificar_firma(msg, "no-es-hex")


def test_claves_derivadas_son_independientes():
    from backend.app.config import derivar_clave
    assert len({derivar_clave(p) for p in ("jwt-hs256", "campos-fernet", "firma-ed25519", "auditoria-hmac")}) == 4


# ---------- Tokens ----------
def test_token_enroll_no_sirve_donde_se_exige_access():
    t = tokens.emitir_token(7, "enroll")
    assert tokens.decodificar_token(t, ("enroll", "access")) == 7
    with pytest.raises(HTTPException) as e:
        tokens.decodificar_token(t, ("access",))
    assert e.value.status_code == 401


def test_token_rechaza_alg_none_expirado_y_audiencia_ajena():
    sin_firma = jwt.encode({"sub": "1", "scope": "access", "iss": tokens.EMISOR, "aud": tokens.AUDIENCIA,
                            "iat": int(time.time()), "exp": int(time.time()) + 60, "jti": "x"}, key=None, algorithm="none")
    expirado = tokens.emitir_token(1, "access", minutos=-1)
    ajeno = jwt.encode({"sub": "1", "scope": "access", "iss": tokens.EMISOR, "aud": "otra-api",
                        "iat": int(time.time()), "exp": int(time.time()) + 60, "jti": "x"},
                       key=crypto.derivar_clave("jwt-hs256") if hasattr(crypto, "derivar_clave") else b"k" * 32,
                       algorithm="HS256")
    for malo in (sin_firma, expirado, ajeno, "basura.token.aqui"):
        with pytest.raises(HTTPException):
            tokens.decodificar_token(malo, ("access",))


# ---------- TOTP anti-repetición ----------
def test_totp_un_solo_uso_y_rechaza_formato_invalido(monkeypatch):
    ahora = {"t": 1_800_000_005.0}
    monkeypatch.setattr(totp_utils, "_ahora", lambda: ahora["t"])
    secreto = totp_utils.generar_secreto()
    codigo = pyotp.TOTP(secreto).at(ahora["t"])
    contador = totp_utils.verificar_codigo(secreto, codigo, 0)
    assert contador is not None
    assert totp_utils.verificar_codigo(secreto, codigo, contador) is None        # repetición bloqueada
    ahora["t"] += 30
    assert totp_utils.verificar_codigo(secreto, pyotp.TOTP(secreto).at(ahora["t"]), contador) is not None
    for malo in ("12345", "1234567", "abcdef", "", "12 345"):
        assert totp_utils.verificar_codigo(secreto, malo, 0) is None


# ---------- Rate limit ----------
def test_limitador_bloquea_al_excederse_y_recupera():
    class Req:                                            # petición mínima simulada
        client = type("C", (), {"host": "10.0.0.9"})()
    lim = rate_limit.LimitadorPorIP("prueba", 3, 1)
    for _ in range(3):
        lim(Req())
    with pytest.raises(HTTPException) as e:
        lim(Req())
    assert e.value.status_code == 429 and "Retry-After" in e.value.headers
    time.sleep(1.1)
    lim(Req())                                            # la ventana se desliza
