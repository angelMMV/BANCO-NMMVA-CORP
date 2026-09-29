# 🤖 Prompt de Ejecución Automatizada para IA Agéntica (NMMVA CORP)

Este documento sirve como instrucción agéntica (*Agentic Prompt Instructions*) de alto nivel para que cualquier modelo de IA con capacidad de ejecución de comandos pueda desplegar y verificar el sistema completo de **NMMVA CORP** en segundo plano de manera autónoma.

---

## 📋 Directiva de la Tarea para la IA

> **Objetivo:** Iniciar autónomamente el servidor Backend (FastAPI) y la Interfaz de Usuario Frontend (Streamlit) del proyecto **NMMVA CORP**, verificar la conectividad de la API y garantizar que la Landing Page e Interfaz de Usuario estén totalmente desplegadas y listas para interacción en `http://localhost:8501`.

---

## 🛠️ Protocolo de Ejecución Paso a Paso para la IA

### 1️⃣ Verificación del Entorno y Pre-requisitos
La IA agéntica debe ejecutar los siguientes comandos para confirmar que el entorno virtual y la base de datos MySQL están disponibles:

```powershell
# 1. Cambiar a la ruta raíz del proyecto
cd C:\Users\angel\Downloads\BANCO-NMMVA-CORP-main\BANCO-NMMVA-CORP-main

# 2. Verificar existencia del entorno virtual (venv)
Test-Path .\venv\Scripts\python.exe

# 3. Verificar que MySQL esté escuchando en el puerto 3306 (Localhost)
Test-NetConnection -ComputerName localhost -Port 3306
```

---

### 2️⃣ Despliegue del Backend (FastAPI) en Segundo Plano
La IA agéntica debe lanzar el script ejecutor del Backend como una tarea asíncrona/de demonio (*daemon process*) para no bloquear la ejecución:

```powershell
# Comando para ejecutar el servidor API Backend:
.\venv\Scripts\python.exe run_backend.py
```
* **Puerto Backend:** `http://127.0.0.1:8000`
* **Verificación de Salud:** La IA debe realizar una solicitud GET a `http://127.0.0.1:8000/` y confirmar el estado HTTP `200 OK`.

---

### 3️⃣ Despliegue del Frontend (Streamlit) en Segundo Plano
Una vez que el Backend reporte salud en el puerto `8000`, la IA agéntica debe lanzar el servidor de interfaz visual:

```powershell
# Comando para ejecutar el servidor Frontend Streamlit:
.\venv\Scripts\python.exe run_frontend.py
```
* **Puerto Frontend / UI:** `http://localhost:8501`
* **Verificación de Salud:** La IA debe realizar un ping a `http://localhost:8501` o abrir la pestaña en el navegador web del usuario.

---

## 🎯 Criterio de Éxito Agéntico (*Definition of Done*)

La IA agéntica debe declarar la tarea como exitosa únicamente cuando haya cumplido los siguientes puntos:

1. [x] **Backend en línea:** `http://127.0.0.1:8000` responde `{"mensaje": "¡Holi! El backend está corriendo al 100%."}`.
2. [x] **Frontend desplegado:** `http://localhost:8501` muestra la Landing Page con el fondo morado oscuro, banner institucional y texto blanco en alta resolución.
3. [x] **Notificación al Usuario:** Proporcionar los enlaces directos y confirmar que ambas terminales se encuentran operativas en segundo plano.

---

## 📄 Prompt Rápido para Copiar y Pegar a otra IA

```markdown
Por favor toma el proyecto en C:\Users\angel\Downloads\BANCO-NMMVA-CORP-main\BANCO-NMMVA-CORP-main y ejecuta autónomamente en segundo plano el backend (python run_backend.py) y el frontend (python run_frontend.py) usando el entorno virtual venv. Confirma que el backend responda en http://127.0.0.1:8000 y notifícame cuando la UI esté desplegada y accesible en http://localhost:8501.
```
