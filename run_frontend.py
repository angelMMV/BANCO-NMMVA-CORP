import subprocess
import sys

if __name__ == "__main__":
    print("🎨 Iniciando Frontend Streamlit de NMMVA CORP...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "frontend/app.py"])
