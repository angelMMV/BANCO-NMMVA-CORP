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

---

## 🔐 Seguridad (STRIDE · MITRE ATT&CK · CIA+ · X.800 · Defensa en Profundidad)

El proyecto fue analizado con **STRIDE** y endurecido aplicando **MITRE ATT&CK, CIA+, ITU-T X.800 y Defensa en Profundidad**.
Documentación completa, evidencia *antes/después* y limitaciones: [`docs/SEGURIDAD.md`](docs/SEGURIDAD.md).

**Novedades principales**
- **Login MFA** (`POST /login`: contraseña + TOTP) con tokens de 15 min; la identidad sale del token, no del cliente.
- Contraseñas con **scrypt** + política de 12 caracteres; TOTP de **un solo uso**; **bloqueo de cuenta** y límite de tasa por IP.
- **TOTP y CURP cifrados** en la base de datos.
- **Firma Ed25519** ligada al hash del documento (`POST /verificar-firma`) y **bitácora encadenada** a prueba de manipulación (`GET /auditoria/verificar`).
- Sin `root` ni claves en el código: configuración por variables de entorno (`NMMVA_*`).

**Flujo actualizado:** Registro → Configurar 2FA → **Iniciar sesión** (Paso 3) → Firmar.

**Antes de actualizar una base ya en uso, haz un respaldo** (`mysqldump nmmva_bank > respaldo.sql`). Los usuarios existentes se migran solos.

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest          # 38 pruebas (usa una base separada: nmmva_bank_test)
```
