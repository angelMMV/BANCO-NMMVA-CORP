"""
Modelos de entrada (DTO) con validación estricta.

Antes: sólo tipos (str/int). Cualquier cadena de cualquier tamaño entraba al sistema.
Ahora: longitudes acotadas, formatos (correo, CURP, TOTP de 6 dígitos), política de contraseñas,
`extra="forbid"` (rechaza campos inesperados) y sin `id_usuario` enviado por el cliente
(la identidad sale del token; ver security/tokens.py).
"""
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.security.passwords import validar_politica

_RE_CORREO = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
_RE_CURP = r"^[A-Z]{4}\d{6}[HMX][A-Z]{2}[A-Z]{3}[A-Z0-9]\d$"
_RE_TOTP = r"^\d{6}$"
_RE_FIRMA = r"^[0-9a-f]{64,128}$"


def _recortar(v):
    return v.strip() if isinstance(v, str) else v


class _Base(BaseModel):
    # Sin str_strip_whitespace global: las contraseñas NO deben alterarse.
    model_config = ConfigDict(extra="forbid")

    @field_validator("nombre_completo", "correo", "totp_code", "documento", "firma", mode="before", check_fields=False)
    @classmethod
    def _recortar_campos_de_texto(cls, v):
        return _recortar(v)


class UsuarioRegistro(_Base):
    """Alta de cuenta."""
    nombre_completo: str = Field(min_length=3, max_length=100)
    correo: str = Field(max_length=100, pattern=_RE_CORREO)
    password: str = Field(max_length=128)
    edad: int = Field(ge=18, le=120)
    curp: str = Field(min_length=18, max_length=18)

    @field_validator("correo")
    @classmethod
    def _correo_minusculas(cls, v: str) -> str:
        return v.lower()

    @field_validator("curp", mode="before")
    @classmethod
    def _curp_mayusculas(cls, v):
        return v.strip().upper() if isinstance(v, str) else v

    @field_validator("curp")
    @classmethod
    def _curp_formato(cls, v: str) -> str:
        if not re.match(_RE_CURP, v):
            raise ValueError("formato de CURP inválido")
        return v

    @model_validator(mode="after")
    def _politica_password(self):
        problemas = validar_politica(self.password, [self.nombre_completo, self.correo])
        if problemas:
            raise ValueError("Contraseña insegura: " + "; ".join(problemas))
        return self


class DatosLogin(_Base):
    correo: str = Field(max_length=100, pattern=_RE_CORREO)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str = Field(pattern=_RE_TOTP)

    @field_validator("correo")
    @classmethod
    def _correo_minusculas(cls, v: str) -> str:
        return v.lower()


class DatosValidacionTOTP(_Base):
    totp_code: str = Field(pattern=_RE_TOTP)


class DatosFirma(_Base):
    documento: str = Field(min_length=1, max_length=255)
    password_confirmacion: str = Field(min_length=1, max_length=128)
    totp_code: str = Field(pattern=_RE_TOTP)


class DatosVerificarFirma(_Base):
    firma: str = Field(pattern=_RE_FIRMA)
