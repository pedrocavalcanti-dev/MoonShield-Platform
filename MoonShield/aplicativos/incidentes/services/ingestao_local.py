import socket
import uuid
import logging
from django.utils import timezone

# Importa o model Sensor e o consumidor atual.
# Ajuste o import do pipeline de acordo com a estrutura exata, se necessário.
from incidentes.models import Sensor
from incidentes.receptor.consumidor import processar_lote

logger = logging.getLogger(__name__)


def _obter_ip_local() -> str:
    """
    Tenta descobrir o IP da interface principal conectando um socket UDP logicamente.
    Não envia dados reais para a internet e retorna 127.0.0.1 em caso de falha.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 8.8.8.8 e porta 80 são usados apenas para o SO rotear o IP correto local
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def obter_sensor_local() -> Sensor:
    """
    Obtém ou cria o registro do sensor local no banco de dados.
    Garante que o token (obrigatório) seja preenchido com UUID único apenas na criação.
    Trata o tamanho do nome para respeitar o limite de 100 caracteres.
    """
    hostname = socket.gethostname().strip().lower() or "moonshield"
    nome_sensor = f"suricata-local-{hostname}"[:100]
    ip_local = _obter_ip_local()

    sensor, created = Sensor.objects.get_or_create(
        nome=nome_sensor,
        defaults={
            "ip": ip_local,
            "token": uuid.uuid4().hex,
            "ativo": True,
        }
    )

    alterado = False
    
    # Atualiza IP se houver mudança de rede, e garante que esteja ativo
    if not created:
        if sensor.ip != ip_local:
            sensor.ip = ip_local
            alterado = True
        if not sensor.ativo:
            sensor.ativo = True
            alterado = True
            
        if alterado:
            sensor.save(update_fields=["ip", "ativo"])

    return sensor


def ingerir_eventos_locais(eventos_brutos: list[dict]) -> dict:
    """
    Recebe uma lista de eventos do Suricata (já como dicionários Python),
    associa ao sensor local e envia para processamento no pipeline padrão.
    """
    resultado = {
        "ok": False,
        "origem": "local",
        "sensor": None,
        "recebidos": 0,
        "validos": 0,
        "invalidos": 0,
        "erro": None
    }

    if not isinstance(eventos_brutos, list):
        resultado["erro"] = "A entrada de eventos deve ser uma lista."
        return resultado

    resultado["recebidos"] = len(eventos_brutos)

    # Filtra apenas o que é dicionário (por segurança)
    eventos_validos = [e for e in eventos_brutos if isinstance(e, dict)]
    resultado["validos"] = len(eventos_validos)
    resultado["invalidos"] = len(eventos_brutos) - len(eventos_validos)

    if not eventos_validos:
        resultado["ok"] = True
        return resultado

    try:
        sensor = obter_sensor_local()
        
        # Aciona o pipeline idêntico ao que o endpoint HTTP usa
        resultado_processamento = processar_lote(eventos_validos, sensor)

        # Atualiza o timestamp (last_seen)
        sensor.last_seen = timezone.now()
        sensor.save(update_fields=["last_seen"])

        # Mescla o resultado retornado pelo consumidor
        if isinstance(resultado_processamento, dict):
            resultado.update(resultado_processamento)
            
        # Garante que os metadados locais sobrescrevam caso a API mude no futuro
        resultado.update({
            "ok": True,
            "origem": "local",
            "sensor": sensor.nome,
            "recebidos": len(eventos_brutos),
            "validos": len(eventos_validos),
            "invalidos": len(eventos_brutos) - len(eventos_validos),
            "last_seen": sensor.last_seen.isoformat(),
        })

    except Exception as e:
        logger.exception("Falha na ingestão local de eventos do Suricata.")
        resultado["erro"] = str(e)

    return resultado