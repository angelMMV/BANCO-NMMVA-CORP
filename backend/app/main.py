from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.app.database import obtener_conexion
from backend.app.routes import auth, totp, signature

app = FastAPI(
    title="NMMVA CORP - Banking API with TOTP 2FA",
    description="RESTful API providing user registration, TOTP 2FA enrollment/verification, and non-repudiation digital contract signing."
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(auth.router)
app.include_router(totp.router)
app.include_router(signature.router)


@app.get("/", tags=["Health Check"])
def inicio():
    """Root health check endpoint."""
    return {"mensaje": "¡Holi! El backend está corriendo al 100%."}


@app.get("/test-db", tags=["Health Check"])
def probar_bd():
    """Database connection testing endpoint."""
    conexion = obtener_conexion()
    if conexion and conexion.is_connected():
        conexion.close()
        return {"status": "Éxito", "mensaje": "¡Conexión a MySQL exitosa!"}
    
    raise HTTPException(status_code=500, detail="No se pudo conectar a la base de datos.")
