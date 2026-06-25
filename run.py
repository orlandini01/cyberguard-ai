"""
run.py — Inicializador do CyberGuard AI.

Windows PowerShell:
    python run.py

Mac/Linux:
    python run.py
"""
import sys
import subprocess
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def check_and_install(packages: list[str]) -> None:
    missing = []
    for pkg, import_name in packages:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"\n  ⚠️  Instalando dependências faltando: {', '.join(missing)}")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
            check=True
        )
        print("  ✅ Instalação concluída\n")

def main():
    print("=" * 55)
    print("  🛡️  CyberGuard AI — Security Intelligence Platform")
    print("  Version 1.0.0")
    print("=" * 55)

    # Verifica e instala dependências críticas se necessário
    check_and_install([
        ("streamlit",    "streamlit"),
        ("pandas",       "pandas"),
        ("plotly",       "plotly"),
        ("sqlalchemy",   "sqlalchemy"),
        ("python-dotenv","dotenv"),
        ("loguru",       "loguru"),
        ("pytest",       "pytest"),
    ])

    # Cria pastas necessárias
    for folder in ["reports", "logs"]:
        (ROOT / folder).mkdir(exist_ok=True)

    print("  ✅ Ambiente verificado")
    print(f"\n  🌐 Acesse: http://localhost:8501")
    print("  ⚡ Pressione Ctrl+C para encerrar\n")
    print("=" * 55 + "\n")

    # Define PYTHONPATH antes de iniciar o Streamlit
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "app" / "main.py")],
        env=env,
        cwd=str(ROOT),   # garante working directory = raiz do projeto
    )

if __name__ == "__main__":
    main()
