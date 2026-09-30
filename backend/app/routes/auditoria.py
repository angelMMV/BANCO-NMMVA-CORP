from fastapi import APIRouter, Depends

from backend.app.database import get_db
from backend.app.security.audit import verificar_cadena
from backend.app.security.rate_limit import lim_consulta
from backend.app.security.tokens import usuario_autenticado

router = APIRouter(prefix="/auditoria", tags=["Auditoría"])


@router.get("/verificar", dependencies=[Depends(lim_consulta)])
def verificar_integridad_bitacora(_: int = Depends(usuario_autenticado), conexion=Depends(get_db)):
    """Recalcula la cadena HMAC de la bitácora y reporta si fue alterada.
    (En un sistema real esto sería exclusivo de un rol de auditor/administrador.)"""
    return verificar_cadena(conexion.cursor())
