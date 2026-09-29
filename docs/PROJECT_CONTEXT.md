# NMMVA CORP - Bitácora del Proyecto y Contexto Técnico

**Fecha de última actualización:** 21 de Septiembre, 2026  
**Ruta del Proyecto:** `C:\Users\angel\Downloads\BANCO-NMMVA-CORP-main\BANCO-NMMVA-CORP-main`

---

## 1. Resumen del Proyecto

**NMMVA CORP** es un prototipo de neobanco 100% digital diseñado con arquitectura modular desglosada en un **Backend (`backend/`)** y un **Frontend (`frontend/`)**, respaldado por una base de datos **MySQL** (`nmmva_bank`).

### Stack Tecnológico
* **Backend:** Python 3.13, FastAPI, Pydantic, MySQL Connector (`mysql-connector-python`).
* **Frontend:** Streamlit, Requests, CSS personalizado Fintech Dark Glassmorphic.
* **Seguridad & Criptografía:** 
  * Hasheo de contraseñas con **SHA-256**.
  * Autenticación de Doble Factor (**2FA TOTP**, RFC 6238) mediante `pyotp` y `qrcode`.
  * Firma digital criptográfica SHA-256 para No-Repudio de contratos.
* **Base de Datos:** MySQL (`nmmva_bank`) con tablas: `usuarios`, `logs_auditoria`, `contratos_firmados`.

---

## 2. Reestructuración Modular de Directorios

El proyecto ha sido organizado en capas independientes de software:

```
BANCO-NMMVA-CORP-main/
│
├── backend/                             # ⚙️ Módulo Backend (FastAPI)
│   ├── app/
│   │   ├── main.py                      # Punto de entrada FastAPI & CORS
│   │   ├── database.py                  # Conexión MySQL & migraciones de columnas
│   │   ├── models.py                    # Schemas y DTOs (Pydantic)
│   │   └── routes/                      # Endpoints por módulo
│   │       ├── auth.py                  # POST /registro
│   │       ├── totp.py                  # POST /totp/setup & /totp/verify
│   │       └── signature.py             # POST /firmar-contrato
│
├── frontend/                            # 🎨 Módulo Frontend (Streamlit)
│   ├── app.py                           # Punto de entrada principal Streamlit
│   ├── api_client.py                    # Cliente HTTP para el backend
│   ├── assets/                          # Logotipo y hojas de estilo CSS
│   ├── components/                      # Componentes reutilizables (Header, Sidebar)
│   └── views/                           # Módulos de vista (Registro, TOTP, Firma)
│
├── docs/                                # Documentación institucional
├── run_backend.py                       # Script ejecutor simple del backend
├── run_frontend.py                      # Script ejecutor simple del frontend
└── requirements.txt                     # Lista de dependencias del proyecto
```

---

## 3. Instrucciones de Ejecución Simplificadas

Con la nueva estructura modular, ejecutar el proyecto es mucho más fácil mediante los scripts ejecutores:

### Terminal 1: Backend
```powershell
python run_backend.py
```

### Terminal 2: Frontend
```powershell
python run_frontend.py
```
