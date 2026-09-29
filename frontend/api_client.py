import requests

BASE_URL = "http://127.0.0.1:8000"

class APIClient:
    """Centralized HTTP API Client for NMMVA CORP Backend."""

    @staticmethod
    def check_health():
        """Checks if backend server is online and responding."""
        try:
            res = requests.get(f"{BASE_URL}/", timeout=3)
            return res.status_code == 200
        except Exception:
            return False

    @staticmethod
    def registrar_usuario(nombre: str, correo: str, password: str, edad: int, curp: str):
        """Sends registration request to backend."""
        payload = {
            "nombre_completo": nombre,
            "correo": correo,
            "password": password,
            "edad": int(edad),
            "curp": curp
        }
        return requests.post(f"{BASE_URL}/registro", json=payload, timeout=5)

    @staticmethod
    def setup_totp(id_usuario: int):
        """Fetches TOTP setup secret and QR Code for user."""
        return requests.post(f"{BASE_URL}/totp/setup/{id_usuario}", timeout=5)

    @staticmethod
    def verify_totp(id_usuario: int, totp_code: str):
        """Verifies 6-digit TOTP code against backend."""
        payload = {
            "id_usuario": id_usuario,
            "totp_code": totp_code
        }
        return requests.post(f"{BASE_URL}/totp/verify", json=payload, timeout=5)

    @staticmethod
    def firmar_contrato(id_usuario: int, documento: str, password_confirmacion: str, totp_code: str):
        """Submits digital contract signing request with MFA verification."""
        payload = {
            "id_usuario": id_usuario,
            "documento": documento,
            "password_confirmacion": password_confirmacion,
            "totp_code": totp_code
        }
        return requests.post(f"{BASE_URL}/firmar-contrato", json=payload, timeout=5)
