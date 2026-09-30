import uvicorn

if __name__ == "__main__":
    print("🚀 Iniciando Backend FastAPI de NMMVA CORP...")
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True,
                server_header=False)   # no anunciar "server: uvicorn" (menos información para el atacante)
