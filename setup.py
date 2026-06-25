"""
setup.py — Permite instalar o pacote src/ em modo editable.

Execute UMA VEZ após criar o venv:
    pip install -e .

Isso resolve definitivamente o ModuleNotFoundError: No module named 'src'
em qualquer ambiente (Windows, Mac, Linux).
"""

from setuptools import setup, find_packages

setup(
    name="cyberguard-ai",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[],
)
