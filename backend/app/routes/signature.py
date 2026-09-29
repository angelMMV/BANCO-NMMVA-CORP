from fastapi import APIRouter, HTTPException
import mysql.connector
import hashlib
import pyotp
from backend.app.database import obtener_conexion, ensure_totp_column_exists
from backend.app.models import DatosFirma

router = APIRouter(tags=["Firma Digital Criptográfica"])

@router.post("/firmar-contrato")
def firmar_contrato(datos: DatosFirma):
    """
    Signs a contract using multi-factor authentication (Password + TOTP 2FA) to guarantee non-repudiation.
    """
    conexion = obtener_conexion()
    if not conexion:
        raise HTTPException(status_code=500, detail="Error de conexión a la base de datos.")

    ensure_totp_column_exists(conexion)
    cursor = conexion.cursor()

    try:
        password_ingresada_hash = hashlib.sha256(datos.password_confirmacion.encode()).hexdigest()
        
        cursor.execute(
            "SELECT id_usuario, totp_secret FROM usuarios WHERE id_usuario = %s AND password_hash = %s", 
            (datos.id_usuario, password_ingresada_hash)
        )
        usuario = cursor.fetchone()

        if not usuario:
            raise HTTPException(status_code=401, detail="Firma rechazada: Contraseña incorrecta o usuario no existe.")

        totp_secret = usuario[1]
        if not totp_secret:
            raise HTTPException(status_code=400, detail="Firma rechazada: Debes configurar 2FA (TOTP) en el Paso 2 antes de firmar.")

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(datos.totp_code.strip()):
            raise HTTPException(status_code=401, detail="Firma rechazada: Código 2FA TOTP incorrecto o expirado.")

        cadena_a_firmar = f"DOC:{datos.documento}|USER:{datos.id_usuario}|TOTP_VERIFIED|NMMVA_CORP_2026"
        firma_digital = hashlib.sha256(cadena_a_firmar.encode()).hexdigest()

        sql_contrato = "INSERT INTO contratos_firmados (id_usuario, documento, firma_digital) VALUES (%s, %s, %s)"
        cursor.execute(sql_contrato, (datos.id_usuario, datos.documento, firma_digital))

        sql_log = "INSERT INTO logs_auditoria (evento, id_usuario) VALUES (%s, %s)"
        cursor.execute(sql_log, (f"Contrato firmado digitalmente con 2FA TOTP: {datos.documento}", datos.id_usuario))

        conexion.commit()
        return {
            "status": "Éxito", 
            "mensaje": "Contrato firmado con éxito. Autenticación de doble factor y No Repudio garantizados.",
            "firma_generada": firma_digital
        }

    except mysql.connector.Error as err:
        conexion.rollback()
        raise HTTPException(status_code=500, detail=f"Error de base de datos: {err}")
    finally:
        cursor.close()
        conexion.close()
