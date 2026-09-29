import mysql.connector

def obtener_conexion():
    """
    Establishes and returns a connection to the MySQL database.
    
    Returns:
        mysql.connector.MySQLConnection or None: Connected MySQL instance or None on error.
    """
    try:
        conexion = mysql.connector.connect(
            host="localhost",
            user="root",
            password="", 
            database="nmmva_bank"
        )
        return conexion
    except mysql.connector.Error as err:
        print(f"[DB Error] Connection failed: {err}")
        return None


def ensure_totp_column_exists(conexion):
    """
    Dynamically verifies and adds the `totp_secret` column to the `usuarios` table
    if it does not already exist.

    Args:
        conexion (mysql.connector.MySQLConnection): Active database connection.
    """
    cursor = conexion.cursor()
    try:
        cursor.execute("""
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = 'nmmva_bank' 
              AND TABLE_NAME = 'usuarios' 
              AND COLUMN_NAME = 'totp_secret'
        """)
        exists = cursor.fetchone()[0]
        if not exists:
            cursor.execute("ALTER TABLE usuarios ADD COLUMN totp_secret VARCHAR(32) NULL")
            conexion.commit()
            print("[DB Migration] Column `totp_secret` added to `usuarios` table.")
    except mysql.connector.Error as err:
        print(f"[DB Migration Error] Could not verify/add `totp_secret` column: {err}")
    finally:
        cursor.close()
