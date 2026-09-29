# NMMVA CORP - Plataforma Neobanco 100% Digital

Prototipo de neobanco enfocado en **ciberseguridad, trazabilidad y firma digital con No Repudio** mediante arquitectura de microservicios con **FastAPI** (Backend) y **Streamlit** (Frontend).

---

## 📁 Estructura del Proyecto

```
BANCO-NMMVA-CORP-main/
│
├── backend/                  # API REST con FastAPI (Routes, Database, Models)
│   └── app/
│       ├── main.py           # Instancia principal de FastAPI
│       ├── database.py       # Conexión MySQL & migraciones
│       ├── models.py         # Schemas DTO (Pydantic)
│       └── routes/           # Endpoints (/registro, /totp, /firmar-contrato)
│
├── frontend/                 # Interfaz de Usuario con Streamlit
│   ├── app.py                # Punto de entrada principal
│   ├── api_client.py         # Cliente HTTP
│   ├── assets/               # Logotipo y hojas CSS
│   ├── components/           # Header y Sidebar
│   └── views/                # Vista Registro, TOTP 2FA y Firma Digital
│
├── docs/                     # Contexto técnico y bitácora
│   └── PROJECT_CONTEXT.md
│
├── run_backend.py            # Lanzador rápido de Backend FastAPI
├── run_frontend.py           # Lanzador rápido de Frontend Streamlit
└── requirements.txt          # Dependencias de Python
```

---

## 🚀 Instrucciones para Ejecución

Asegúrate de tener corriendo tu servidor **MySQL / XAMPP** en `localhost` con la base de datos `nmmva_bank`.

### 1️⃣ Terminal 1: Backend (FastAPI)
```powershell
.\venv\Scripts\activate
python run_backend.py
```
*Backend escuchando en `http://127.0.0.1:8000`.*

### 2️⃣ Terminal 2: Frontend (Streamlit)
```powershell
.\venv\Scripts\activate
python run_frontend.py
```
*Abre automáticamente la interfaz en `http://localhost:8501`.*
