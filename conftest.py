"""
conftest.py — Arquivo na RAIZ do projeto.

O pytest detecta este arquivo automaticamente e adiciona
a raiz do projeto ao sys.path. Isso resolve o erro:
"No module named 'src'" ao rodar python -m pytest

NÃO REMOVA ESTE ARQUIVO.
"""
import sys
from pathlib import Path

# Garante que cyberguard-ai/ está no path
sys.path.insert(0, str(Path(__file__).resolve().parent))
