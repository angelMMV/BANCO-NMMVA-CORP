import os

import requests

# En producción define NMMVA_API_URL con https:// (el TLS lo termina un proxy inverso; ver docs/SEGURIDAD.md).
BASE_URL = os.getenv("NMMVA_API_URL", "http://127.0.0.1:8000")
TIMEOUT = 15   # el hash de contraseñas (scrypt) es deliberadamente lento


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class APIClient:
    """Cliente HTTP centralizado del backend NMMVA CORP. Las rutas protegidas reciben el token (Bearer)."""

    @staticmethod
    def check_health():
        try:
            return requests.get(f"{BASE_URL}/", timeout=3).status_code == 200
        except Exception:
            return False

    @staticmethod
    def mensaje_error(res, defecto: str = "Ocurrió un error en el servidor.") -> str:
        """Texto de error amigable (maneja 422/429/401 sin mostrar detalles técnicos)."""
        try:
            detalle = res.json().get("detail", defecto)
        except Exception:
            detalle = defecto
        return detalle if isinstance(detalle, str) else defecto

    @staticmethod
    def registrar_usuario(nombre: str, correo: str, password: str, edad: int, curp: str):
        payload = {"nombre_completo": nombre, "correo": correo, "password": password,
                   "edad": int(edad), "curp": curp}
        return requests.post(f"{BASE_URL}/registro", json=payload, timeout=TIMEOUT)

    @staticmethod
    def login(correo: str, password: str, totp_code: str):
        payload = {"correo": correo, "password": password, "totp_code": totp_code}
        return requests.post(f"{BASE_URL}/login", json=payload, timeout=TIMEOUT)

    @staticmethod
    def setup_totp(token: str):
        return requests.post(f"{BASE_URL}/totp/setup", headers=_auth(token), timeout=TIMEOUT)

    @staticmethod
    def verify_totp(token: str, totp_code: str):
        return requests.post(f"{BASE_URL}/totp/verify", json={"totp_code": totp_code},
                             headers=_auth(token), timeout=TIMEOUT)

    @staticmethod
    def firmar_contrato(token: str, documento: str, password_confirmacion: str, totp_code: str):
        payload = {"documento": documento, "password_confirmacion": password_confirmacion,
                   "totp_code": totp_code}
        return requests.post(f"{BASE_URL}/firmar-contrato", json=payload, headers=_auth(token), timeout=TIMEOUT)

    @staticmethod
    def verificar_firma(token: str, firma: str):
        return requests.post(f"{BASE_URL}/verificar-firma", json={"firma": firma},
                             headers=_auth(token), timeout=TIMEOUT)
