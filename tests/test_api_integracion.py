"""Pruebas de integración: recorren los flujos reales de la API contra MySQL/MariaDB."""
import hashlib

import pyotp

from backend.app.config import MAX_INTENTOS_FALLIDOS

PW = "Caballo-Grapa-Nube-77"


def registrar(client, correo="ana@example.com", curp="GOMA900101HDFRRN09", pw=PW, nombre="Ana Gómez"):
    return client.post("/registro", json={"nombre_completo": nombre, "correo": correo,
                                          "password": pw, "edad": 30, "curp": curp})


def hdr(token):
    return {"Authorization": f"Bearer {token}"}


def usuario_con_2fa(client, reloj, **kw):
    """Registro + enrolamiento + confirmación de TOTP. Devuelve (id, secreto, token_enroll)."""
    r = registrar(client, **kw)
    assert r.status_code == 200, r.text
    d = r.json()
    s = client.post("/totp/setup", headers=hdr(d["token"])).json()["totp_secret"]
    v = client.post("/totp/verify", json={"totp_code": reloj.codigo(s)}, headers=hdr(d["token"]))
    assert v.status_code == 200, v.text
    return d["id_usuario"], s, d["token"]


def login(client, correo, pw, secreto, reloj):
    return client.post("/login", json={"correo": correo, "password": pw, "totp_code": reloj.codigo(secreto)})


# ───────────────────────── Registro / datos en reposo ─────────────────────────
def test_registro_guarda_hash_scrypt_y_curp_cifrada(client, sql):
    assert registrar(client).status_code == 200
    pw_hash, curp, idx = sql("SELECT password_hash, curp, curp_idx FROM usuarios")[0]
    assert pw_hash.startswith("scrypt$") and PW not in pw_hash
    assert curp.startswith("enc1:") and "GOMA900101" not in curp
    assert len(idx) == 64


def test_registro_rechaza_contrasena_debil_sin_reflejarla(client):
    r = registrar(client, pw="password1234")
    assert r.status_code == 422
    assert "password1234" not in r.text                 # la respuesta no repite el dato sensible


def test_registro_duplicado_respuesta_generica(client):
    assert registrar(client).status_code == 200
    r1 = registrar(client, curp="XXXX900101HDFRRN09")               # mismo correo
    r2 = registrar(client, correo="otra@example.com")               # misma CURP
    assert r1.status_code == r2.status_code == 409 and r1.json() == r2.json()


def test_registro_valida_formatos_y_campos_extra(client):
    assert registrar(client, curp="CURP-INVALIDA-123").status_code == 422
    assert registrar(client, correo="no-es-correo").status_code == 422
    r = client.post("/registro", json={"nombre_completo": "Ana Gómez", "correo": "a@b.com", "password": PW,
                                       "edad": 30, "curp": "GOMA900101HDFRRN09", "rol": "admin"})
    assert r.status_code == 422                                     # extra="forbid"


def test_inyeccion_sql_no_tiene_efecto(client, sql):
    r = registrar(client, correo="x@y.com", nombre="Robert'); DROP TABLE usuarios;--")
    assert r.status_code == 200
    assert sql("SELECT COUNT(*) FROM usuarios")[0][0] == 1          # la tabla sigue existiendo


# ───────────────────────── Autenticación / autorización ─────────────────────────
def test_endpoints_protegidos_exigen_token(client):
    assert client.post("/totp/setup").status_code == 401
    assert client.post("/totp/verify", json={"totp_code": "123456"}).status_code == 401
    assert client.post("/firmar-contrato", json={"documento": "x", "password_confirmacion": "x",
                                                 "totp_code": "123456"}).status_code == 401
    assert client.get("/auditoria/verificar").status_code == 401
    assert client.post("/totp/setup", headers=hdr("token.falso.aqui")).status_code == 401


def test_la_identidad_sale_del_token_no_del_cliente(client):
    a = registrar(client).json()
    b = registrar(client, correo="beto@example.com", curp="PEPB850505HDFRRN01", nombre="Beto Pérez").json()
    sa = client.post("/totp/setup", headers=hdr(a["token"])).json()
    sb = client.post("/totp/setup", headers=hdr(b["token"])).json()
    assert sa["id_usuario"] == a["id_usuario"] and sb["id_usuario"] == b["id_usuario"]
    assert sa["totp_secret"] != sb["totp_secret"]


def test_secreto_totp_cifrado_en_bd_y_no_reexpuesto_tras_confirmar(client, reloj, sql):
    uid, secreto, token = usuario_con_2fa(client, reloj)
    guardado = sql("SELECT totp_secret FROM usuarios WHERE id_usuario=%s", (uid,))[0][0]
    assert guardado.startswith("enc1:") and secreto not in guardado
    assert client.post("/totp/setup", headers=hdr(token)).status_code == 409   # ya no se puede volver a leer


def test_token_de_enrolamiento_no_puede_firmar(client, reloj):
    _, secreto, token_enroll = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    r = client.post("/firmar-contrato", headers=hdr(token_enroll),
                    json={"documento": "Contrato", "password_confirmacion": PW, "totp_code": reloj.codigo(secreto)})
    assert r.status_code == 401


def test_totp_no_se_puede_reutilizar(client, reloj):
    r = registrar(client).json()
    s = client.post("/totp/setup", headers=hdr(r["token"])).json()["totp_secret"]
    codigo = reloj.codigo(s)
    assert client.post("/totp/verify", json={"totp_code": codigo}, headers=hdr(r["token"])).status_code == 200
    again = client.post("/totp/verify", json={"totp_code": codigo}, headers=hdr(r["token"]))
    assert again.status_code == 401                                  # mismo código, segundo uso -> rechazado


def test_login_exige_2fa_y_no_revela_si_el_usuario_existe(client, reloj):
    _, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    ok = login(client, "ana@example.com", PW, secreto, reloj)
    assert ok.status_code == 200 and ok.json()["token"]
    mal_pw = client.post("/login", json={"correo": "ana@example.com", "password": "incorrecta-123", "totp_code": "000000"})
    inexistente = client.post("/login", json={"correo": "nadie@example.com", "password": PW, "totp_code": "000000"})
    assert mal_pw.status_code == inexistente.status_code == 401
    assert mal_pw.json() == inexistente.json()                       # mismo mensaje: sin enumeración de usuarios


def test_bloqueo_de_cuenta_por_fuerza_bruta(client, reloj, sql):
    _, secreto, _ = usuario_con_2fa(client, reloj)
    for _ in range(MAX_INTENTOS_FALLIDOS):
        assert client.post("/login", json={"correo": "ana@example.com", "password": "mala-contraseña-1",
                                           "totp_code": "000000"}).status_code == 401
        client.app  # (los límites por IP se reinician abajo para aislar el bloqueo de cuenta)
        from backend.app.security import rate_limit; rate_limit.reiniciar_todos()
    reloj.avanzar()
    r = login(client, "ana@example.com", PW, secreto, reloj)          # credenciales CORRECTAS pero cuenta bloqueada
    assert r.status_code == 401
    assert sql("SELECT COUNT(*) FROM auditoria_segura WHERE severidad='ALERTA'")[0][0] >= 1


def test_rate_limit_por_ip_en_login(client):
    codigos = [client.post("/login", json={"correo": "z@z.com", "password": "x", "totp_code": "000000"}).status_code
               for _ in range(12)]
    assert 429 in codigos and codigos[0] == 401
    assert client.post("/login", json={"correo": "z@z.com", "password": "x", "totp_code": "000000"}).headers["Retry-After"]


# ───────────────────────── Firma digital / No repudio ─────────────────────────
def firmar_flujo(client, reloj, doc="Contrato de Apertura de Cuenta"):
    uid, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    tok = login(client, "ana@example.com", PW, secreto, reloj).json()["token"]
    reloj.avanzar()
    r = client.post("/firmar-contrato", headers=hdr(tok),
                    json={"documento": doc, "password_confirmacion": PW, "totp_code": reloj.codigo(secreto)})
    return uid, secreto, tok, r


def test_firma_ed25519_verificable_y_ligada_al_documento(client, reloj, sql):
    uid, _, tok, r = firmar_flujo(client, reloj)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["algoritmo"] == "Ed25519" and len(d["firma_generada"]) == 128
    assert d["documento_sha256"] == hashlib.sha256(b"Contrato de Apertura de Cuenta").hexdigest()
    assert client.post("/verificar-firma", headers=hdr(tok), json={"firma": d["firma_generada"]}).json()["valida"] is True
    # El atacante con acceso a MySQL cambia el texto del contrato -> se detecta
    sql("UPDATE contratos_firmados SET documento=%s WHERE id_usuario=%s", ("Contrato ALTERADO", uid))
    v = client.post("/verificar-firma", headers=hdr(tok), json={"firma": d["firma_generada"]}).json()
    assert v["valida"] is False and v["documento_integro"] is False and v["firma_autentica"] is True


def test_la_firma_ya_no_es_calculable_por_un_tercero(client, reloj):
    uid, _, _, r = firmar_flujo(client, reloj)
    vieja_formula = hashlib.sha256(
        f"DOC:Contrato de Apertura de Cuenta|USER:{uid}|TOTP_VERIFIED|NMMVA_CORP_2026".encode()).hexdigest()
    assert r.json()["firma_generada"] != vieja_formula               # antes cualquiera podía forjarla


def test_firma_exige_totp_nuevo_no_el_del_login(client, reloj):
    uid, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    lg = login(client, "ana@example.com", PW, secreto, reloj)
    tok = lg.json()["token"]
    r = client.post("/firmar-contrato", headers=hdr(tok),           # mismo intervalo de 30 s que el login
                    json={"documento": "X", "password_confirmacion": PW, "totp_code": reloj.codigo(secreto)})
    assert r.status_code == 401


def test_firma_con_password_incorrecta_se_rechaza_y_no_guarda(client, reloj, sql):
    uid, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    tok = login(client, "ana@example.com", PW, secreto, reloj).json()["token"]
    reloj.avanzar()
    r = client.post("/firmar-contrato", headers=hdr(tok),
                    json={"documento": "X", "password_confirmacion": "incorrecta-999", "totp_code": reloj.codigo(secreto)})
    assert r.status_code == 401 and sql("SELECT COUNT(*) FROM contratos_firmados")[0][0] == 0


def test_un_usuario_no_puede_verificar_firmas_de_otro(client, reloj):
    _, _, _, r = firmar_flujo(client, reloj)
    firma = r.json()["firma_generada"]
    _, s2, _ = usuario_con_2fa(client, reloj, correo="beto@example.com", curp="PEPB850505HDFRRN01", nombre="Beto Pérez")
    reloj.avanzar()
    tok2 = login(client, "beto@example.com", PW, s2, reloj).json()["token"]
    assert client.post("/verificar-firma", headers=hdr(tok2), json={"firma": firma}).status_code == 404


# ───────────────────────── Bitácora a prueba de manipulación ─────────────────────────
def test_cadena_de_auditoria_detecta_edicion_y_borrado(client, reloj, sql):
    _, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    tok = login(client, "ana@example.com", PW, secreto, reloj).json()["token"]
    ok = client.get("/auditoria/verificar", headers=hdr(tok)).json()
    assert ok["integra"] is True and ok["registros"] >= 4
    ids = [f[0] for f in sql("SELECT id FROM auditoria_segura ORDER BY id")]

    sql("UPDATE auditoria_segura SET evento='Nada raro pasó' WHERE id=%s", (ids[1],))      # edición
    mal = client.get("/auditoria/verificar", headers=hdr(tok)).json()
    assert mal["integra"] is False and mal["primer_registro_alterado"] == ids[1]

    sql("UPDATE auditoria_segura SET evento=(SELECT evento FROM (SELECT evento FROM auditoria_segura WHERE id=%s) t) WHERE id=%s", (ids[1], ids[1]))
    sql("DELETE FROM auditoria_segura WHERE id=%s", (ids[2],))                              # borrado intermedio
    assert client.get("/auditoria/verificar", headers=hdr(tok)).json()["integra"] is False


def test_el_log_no_permite_inyeccion_de_lineas(client, reloj, sql):
    uid, secreto, _ = usuario_con_2fa(client, reloj)
    reloj.avanzar()
    tok = login(client, "ana@example.com", PW, secreto, reloj).json()["token"]
    reloj.avanzar()
    client.post("/firmar-contrato", headers=hdr(tok), json={"documento": "Doc\n2026-01-01 FALSO evento\r\nX",
                "password_confirmacion": PW, "totp_code": reloj.codigo(secreto)})
    eventos = [e[0] for e in sql("SELECT evento FROM auditoria_segura WHERE evento LIKE 'Contrato firmado%'")]
    assert eventos and all("\n" not in e and "\r" not in e for e in eventos)


# ───────────────────────── Perímetro ─────────────────────────
def test_cabeceras_de_seguridad_y_errores_genericos(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store" and "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_cors_solo_permite_el_frontend_legitimo(client):
    ok = client.options("/login", headers={"Origin": "http://localhost:8501", "Access-Control-Request-Method": "POST"})
    mal = client.options("/login", headers={"Origin": "https://sitio-malicioso.com", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:8501"
    assert "access-control-allow-origin" not in mal.headers


def test_host_header_no_autorizado_es_rechazado(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
