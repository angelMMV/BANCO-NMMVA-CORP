from fastapi import HTTPException, Request


def ip_cliente(request: Request) -> str:
    return request.client.host if request.client else "desconocida"


def fallar(conexion, codigo: int, detalle: str):
    """Confirma lo escrito hasta ahora (contadores de fallos y auditoría) y responde con error.
    Sin este commit, el registro del intento fallido se perdería con el rollback."""
    conexion.commit()
    raise HTTPException(status_code=codigo, detail=detalle)


MSG_CREDENCIALES = "Credenciales inválidas o cuenta bloqueada temporalmente."   # mismo texto siempre: sin enumeración
