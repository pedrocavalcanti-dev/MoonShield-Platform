"""
MoonShield Agent — Firewall / Núcleo
====================================

Pacote principal do núcleo privilegiado do Firewall MoonShield.

Os módulos são carregados diretamente pelo servidor IPC quando necessários.
Este arquivo não deve importar módulos opcionais/legados para evitar que uma
falha isolada impeça o carregamento de todo o Firewall.
"""

__all__ = []