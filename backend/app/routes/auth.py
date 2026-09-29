from fastapi import APIRouter, HTTPException
import mysql.connector
import hashlib
from backend.app.database import obtener_conexion, ensure_totp_column_exists
from backend.app.models import UsuarioRegistro

router = APIRouter(tags=["Autenticación y Usuarios"])

@router.post("/registro")
def registrar_usuario(usuario: UsuarioRegistro):
    """
    Registers a new user account in the database and records an audit log entry.
    """
    conexion = obtener_conexion()
    if not conexion:
        raise HTTPException(status_code=500, detail="Error de conexión a la base de datos.")
        
    ensure_totp_column_exists(conexion)
    cursor = conexion.cursor()
    password_encriptada = hashlib.sha256(usuario.password.encode()).hexdigest()
    
    try:
        sql_usuario = """
            INSERT INTO usuarios (nombre_completo, correo, password_hash, edad, curp)
            VALUES (%s, %s, %s, %s, %s)
        """
        valores = (usuario.nombre_completo, usuario.correo, password_encriptada, usuario.edad, usuario.curp)
        cursor.execute(sql_usuario, valores)
        id_nuevo_usuario = cursor.lastrowid
        
        sql_log = "INSERT INTO logs_auditoria (evento, id_usuario) VALUES (%s, %s)"
        cursor.execute(sql_log, ("Registro de usuario creado exitosamente", id_nuevo_usuario))
        conexion.commit()
        
        return {
            "status": "Éxito", 
            "mensaje": "Cuenta bancaria creada exitosamente", 
            "id_usuario": id_nuevo_usuario
        }
        
    except mysql.connector.Error as err:
        conexion.rollback() 
        raise HTTPException(status_code=400, detail=f"Error al registrar: {err}")
        
    finally:
        cursor.close()
        conexion.close()
