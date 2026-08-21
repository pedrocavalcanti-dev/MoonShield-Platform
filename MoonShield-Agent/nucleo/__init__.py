"""
MoonShield Agent — Núcleo do Firewall.

Este pacote não importa componentes automaticamente.

Os módulos atuais devem ser importados diretamente pelos consumidores:

    firewall.nucleo.status
    firewall.nucleo.instalador
    firewall.nucleo.aplicador
    firewall.nucleo.rollback
    firewall.nucleo.seguranca
    firewall.nucleo.analisador

Isso evita dependências circulares e referências a módulos legados
removidos da arquitetura atual do MoonShield-Agent.
"""

__all__ = []
