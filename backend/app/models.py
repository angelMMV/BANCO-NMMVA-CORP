from pydantic import BaseModel

class UsuarioRegistro(BaseModel):
    """Data transfer object for new user account registration."""
    nombre_completo: str
    correo: str
    password: str
    edad: int
    curp: str


class DatosValidacionTOTP(BaseModel):
    """Data transfer object for verifying a 6-digit TOTP authentication token."""
    id_usuario: int
    totp_code: str


class DatosFirma(BaseModel):
    """Data transfer object for digital contract signing with multi-factor authentication."""
    id_usuario: int
    documento: str
    password_confirmacion: str
    totp_code: str
