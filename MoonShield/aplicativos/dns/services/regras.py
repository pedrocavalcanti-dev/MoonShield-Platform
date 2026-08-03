import logging
from .adguard_client import AdGuardClient

logger = logging.getLogger(__name__)

def _formatar_regras_inteligente(raw_text: str, mode: str = "block") -> list:
    """
    Converte texto livre em regras AdGuard válidas.
    Aplica a lógica de duplicar com/sem '.br' automaticamente.
    """
    rules = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Se já é uma regra avançada digitada manualmente, mantém intacta
        if line.startswith(("||", "@@", "!", "#", "/", "0.0.0.0", "127.")):
            rules.append(line)
            continue

        # Lógica automática do ".br" (gera para o domínio com e sem .br)
        domains = [line]
        if line.endswith(".br"):
            domains.append(line[:-3])  # Adiciona versão sem .br
        else:
            domains.append(line + ".br")  # Adiciona variação com .br

        # Aplica a sintaxe para todas as variações geradas
        for d in domains:
            if mode == "allow":
                rules.append(f"@@||{d}^")
            else:
                rules.append(f"||{d}^")

    return rules


def adicionar_regras(client: AdGuardClient, raw_text: str, mode: str = "block") -> dict:
    """
    Lê as regras atuais do AdGuard, formata as novas regras, junta tudo
    (evitando duplicatas) e envia a lista completa de volta (Append Seguro).
    """
    novas_regras = _formatar_regras_inteligente(raw_text, mode=mode)

    # Puxa regras atuais e garante lista (NUNCA None)
    regras_atuais = client.get_custom_rules() or []
    if not isinstance(regras_atuais, list):
        logger.warning(
            "get_custom_rules retornou %s — normalizando para lista vazia",
            type(regras_atuais),
        )
        regras_atuais = []

    set_atuais = set(regras_atuais)

    adicionadas = []
    ignoradas = []

    for regra in novas_regras:
        if regra in set_atuais:
            ignoradas.append(regra)
        else:
            adicionadas.append(regra)
            regras_atuais.append(regra)
            set_atuais.add(regra)

    # Se teve novidade, salva a lista inteira por cima
    if adicionadas:
        client.set_custom_rules(regras_atuais)

    return {
        "added": adicionadas,
        "skipped": ignoradas,
        "total": len(regras_atuais),
    }