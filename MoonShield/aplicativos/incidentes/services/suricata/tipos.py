"""
Tipos, Enums e Dataclasses compartilhados para o serviço Suricata do MoonShield.
Este módulo não possui dependências de infraestrutura, Django ou sistema operacional,
e foca apenas no transporte e padronização de dados.
"""

from enum import Enum
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any


def _serializar_valor(valor: Any) -> Any:
    """
    Função privada auxiliar para serializar valores recursivamente,
    convertendo Enums, Datetimes e Dataclasses para tipos nativos JSON.
    """
    if isinstance(valor, Enum):
        return valor.value
    if isinstance(valor, Path):
        return str(valor)
    if isinstance(valor, datetime):
        return valor.isoformat()
    if hasattr(valor, "to_dict") and callable(getattr(valor, "to_dict")):
        return valor.to_dict()
    if isinstance(valor, dict):
        return {k: _serializar_valor(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [_serializar_valor(v) for v in valor]
    if isinstance(valor, tuple):
        return tuple(_serializar_valor(v) for v in valor)
    return valor


class NivelLog(Enum):
    """Níveis de log para execução de tarefas e diagnósticos."""
    INFO = "info"
    SUCESSO = "sucesso"
    AVISO = "aviso"
    ERRO = "erro"
    DEBUG = "debug"


class StatusEtapa(Enum):
    """Status de execução de uma etapa ou tarefa."""
    PENDENTE = "pendente"
    EXECUTANDO = "executando"
    SUCESSO = "sucesso"
    ERRO = "erro"
    CANCELADO = "cancelado"
    IGNORADO = "ignorado"


class TipoTarefaSuricata(Enum):
    """Tipos de tarefas assíncronas suportadas pelo Suricata Helper."""
    DIAGNOSTICO = "diagnostico"
    INSTALACAO = "instalacao"
    CONFIGURACAO = "configuracao"
    ATUALIZACAO_REGRAS = "atualizacao_regras"
    VALIDACAO = "validacao"
    REINICIO_SURICATA = "reinicio_suricata"
    REINICIO_MONITOR = "reinicio_monitor"


class EstadoServico(Enum):
    """Estado de um serviço no sistema operacional (ex: systemd)."""
    ATIVO = "ativo"
    INATIVO = "inativo"
    FALHOU = "falhou"
    DESCONHECIDO = "desconhecido"
    NAO_INSTALADO = "nao_instalado"


class ModoCaptura(Enum):
    """Modos de captura de rede do IDS."""
    SOMENTE_LAN = "lan"
    LAN_WAN = "lan_wan"
    PERSONALIZADO = "personalizado"


@dataclass
class LogExecucao:
    """Representa uma linha de log registrada durante a execução de uma etapa."""
    nivel: NivelLog
    mensagem: str
    etapa: str = ""
    detalhes: dict[str, Any] = field(default_factory=dict)
    criado_em: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Converte o log em um dicionário serializável."""
        return _serializar_valor(self.__dict__)


@dataclass
class ResultadoComando:
    """Transporta o resultado seguro da execução de um subprocesso do sistema."""
    argumentos: list[str]
    codigo: int
    stdout: str = ""
    stderr: str = ""
    sucesso: bool = False
    duracao_segundos: float = 0.0
    timeout: bool = False
    comando_encontrado: bool = True
    iniciado_em: datetime | None = None
    finalizado_em: datetime | None = None
    erro: str = ""

    @property
    def saida(self) -> str:
        """Retorna o stdout, ou stderr como fallback caso stdout esteja vazio."""
        return self.stdout if self.stdout else self.stderr

    @property
    def falhou(self) -> bool:
        """Inverso semântico de sucesso."""
        return not self.sucesso

    def to_dict(self) -> dict[str, Any]:
        """Converte o resultado do comando para um dicionário serializável."""
        d = self.__dict__.copy()
        d["saida"] = self.saida
        d["falhou"] = self.falhou
        return _serializar_valor(d)


@dataclass
class ResultadoEtapa:
    """Mantém o estado, logs e dados processados em uma etapa isolada da lógica de negócios."""
    etapa: str
    status: StatusEtapa
    sucesso: bool
    mensagem: str
    detalhes: str = ""
    dados: dict[str, Any] = field(default_factory=dict)
    logs: list[LogExecucao] = field(default_factory=list)
    erro: str = ""
    iniciado_em: datetime | None = None
    finalizado_em: datetime | None = None

    def adicionar_log(self, mensagem: str, nivel: NivelLog = NivelLog.INFO, detalhes: dict[str, Any] | None = None) -> None:
        """Acrescenta um registro de log à etapa atual."""
        self.logs.append(LogExecucao(
            nivel=nivel,
            mensagem=mensagem,
            etapa=self.etapa,
            detalhes=detalhes or {}
        ))

    def finalizar_sucesso(self, mensagem: str | None = None, dados: dict[str, Any] | None = None) -> None:
        """Marca a etapa como concluída com sucesso."""
        self.sucesso = True
        self.status = StatusEtapa.SUCESSO
        if mensagem:
            self.mensagem = mensagem
        if dados:
            self.dados.update(dados)
        self.finalizado_em = datetime.now()

    def finalizar_erro(self, mensagem: str, erro: str = "", dados: dict[str, Any] | None = None) -> None:
        """Marca a etapa com falha."""
        self.sucesso = False
        self.status = StatusEtapa.ERRO
        self.mensagem = mensagem
        if erro:
            self.erro = erro
        if dados:
            self.dados.update(dados)
        self.finalizado_em = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Converte o resultado da etapa em dicionário serializável."""
        return _serializar_valor(self.__dict__)


@dataclass
class InterfaceRede:
    """Descreve as propriedades de uma interface de rede de nível de sistema operacional."""
    nome: str
    ip: str = ""
    cidr: str = ""
    rede: str = ""
    estado: str = "desconhecido"
    rx_pkts: int = 0
    tx_pkts: int = 0
    rota_padrao: bool = False
    virtual: bool = False
    loopback: bool = False
    mac: str = ""
    mtu: int | None = None
    velocidade_mbps: int | None = None

    @property
    def ativa(self) -> bool:
        """Identifica se a interface está UP ou ativa (mesmo como unknown em casos virtuais)."""
        return self.estado in ("up", "unknown")

    @property
    def possui_ipv4(self) -> bool:
        """Checa se IP e a sub-rede estão definidos."""
        return bool(self.ip and self.cidr)

    def to_dict(self) -> dict[str, Any]:
        """Converte a interface para dicionário."""
        d = self.__dict__.copy()
        d["ativa"] = self.ativa
        d["possui_ipv4"] = self.possui_ipv4
        return _serializar_valor(d)


@dataclass
class TopologiaRede:
    """Mantém a visão global das interfaces de rede detectadas."""
    interfaces: list[InterfaceRede] = field(default_factory=list)
    wan_sugerida: str = ""
    lan_sugerida: str = ""
    interface_mgmt_sugerida: str = ""
    rota_padrao_encontrada: bool = False
    detectada_em: datetime = field(default_factory=datetime.now)
    avisos: list[str] = field(default_factory=list)

    def obter_interface(self, nome: str) -> InterfaceRede | None:
        """Retorna uma interface de rede específica se existir na topologia."""
        for iface in self.interfaces:
            if iface.nome == nome:
                return iface
        return None

    def to_dict(self) -> dict[str, Any]:
        """Converte a topologia para dicionário serializável."""
        return _serializar_valor(self.__dict__)


@dataclass
class DiagnosticoItem:
    """Item individual inspecionado durante o diagnóstico de sistema."""
    id: str
    grupo: str
    titulo: str
    ok: bool
    detalhe: str = ""
    acao: str = ""
    critico: bool = False
    dados: dict[str, Any] = field(default_factory=dict)
    duracao_segundos: float = 0.0

    @property
    def status(self) -> str:
        """Deriva o status de exibição com base no nível de acerto e criticidade."""
        if self.ok:
            return "ok"
        return "erro" if self.critico else "aviso"

    def to_dict(self) -> dict[str, Any]:
        """Converte o item do diagnóstico em dicionário serializável."""
        d = self.__dict__.copy()
        d["status"] = self.status
        return _serializar_valor(d)


@dataclass
class ResultadoDiagnostico:
    """Estrutura completa e consolidada do diagnóstico da infraestrutura do IDS."""
    itens: list[DiagnosticoItem] = field(default_factory=list)
    executado_em: datetime = field(default_factory=datetime.now)
    duracao_segundos: float = 0.0
    erro_geral: str = ""

    @property
    def total_checks(self) -> int:
        return len(self.itens)

    @property
    def total_ok(self) -> int:
        return sum(1 for item in self.itens if item.ok)

    @property
    def total_falhas(self) -> int:
        return sum(1 for item in self.itens if not item.ok)

    @property
    def total_criticos(self) -> int:
        return sum(1 for item in self.itens if not item.ok and item.critico)

    @property
    def pronto(self) -> bool:
        """Determina se o sistema está operacional para funcionamento básico sem falhas graves."""
        if not self.itens:
            return False
        return self.total_criticos == 0

    @property
    def grupos(self) -> dict[str, list[DiagnosticoItem]]:
        """Agrupa os itens do diagnóstico por seu grupo lógico."""
        _grupos: dict[str, list[DiagnosticoItem]] = {}
        for item in self.itens:
            _grupos.setdefault(item.grupo, []).append(item)
        return _grupos

    def adicionar(self, item: DiagnosticoItem) -> None:
        """Adiciona um item ao resultado do diagnóstico."""
        self.itens.append(item)

    def obter(self, id_item: str) -> DiagnosticoItem | None:
        """Obtém um item do diagnóstico pelo seu ID único."""
        for item in self.itens:
            if item.id == id_item:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        """Converte todo o resultado do diagnóstico para um JSON/Dict seguro."""
        d = self.__dict__.copy()
        d["ok"] = (self.total_falhas == 0)
        d["pronto"] = self.pronto
        d["total_checks"] = self.total_checks
        d["total_ok"] = self.total_ok
        d["total_falhas"] = self.total_falhas
        d["total_criticos"] = self.total_criticos
        d["grupos"] = self.grupos
        return _serializar_valor(d)


@dataclass
class ConfiguracaoSuricataDados:
    """Estrutura temporária e validável para manipular configurações do Suricata antes de persistir no banco."""
    interface_wan: str = ""
    interface_lan: str = ""
    interface_mgmt: str = ""
    interfaces_monitoradas: list[str] = field(default_factory=list)
    home_net: list[str] = field(default_factory=list)
    dns_interno: str = ""
    yaml_path: str = "/etc/suricata/suricata.yaml"
    eve_path: str = "/var/log/suricata/eve.json"
    modo_captura: ModoCaptura = ModoCaptura.LAN_WAN
    instalar_et_open: bool = True
    instalar_regras_moonshield: bool = True
    reiniciar_servicos: bool = True

    def validar(self) -> list[str]:
        """Valida a integridade semântica dos dados sem interagir com o SO ou infraestrutura."""
        erros = []
        if not self.interface_wan:
            erros.append("A interface WAN é obrigatória.")
        if not self.interface_lan:
            erros.append("A interface LAN é obrigatória.")
        if self.interface_wan and self.interface_lan and self.interface_wan == self.interface_lan:
            erros.append("A interface WAN e LAN não podem ser iguais.")
        
        if not self.interfaces_monitoradas:
            erros.append("Pelo menos uma interface deve ser monitorada.")
        if any(not iface for iface in self.interfaces_monitoradas):
            erros.append("A lista de interfaces monitoradas contém valores vazios.")
            
        if not self.home_net:
            erros.append("A lista HOME_NET deve conter pelo menos uma rede.")
            
        if not self.yaml_path:
            erros.append("O caminho do suricata.yaml não pode estar vazio.")
        if not self.eve_path:
            erros.append("O caminho do eve.json não pode estar vazio.")

        if self.modo_captura == ModoCaptura.SOMENTE_LAN:
            if self.interface_lan not in self.interfaces_monitoradas:
                erros.append("No modo SOMENTE_LAN, a interface LAN precisa estar nas interfaces monitoradas.")
        elif self.modo_captura == ModoCaptura.LAN_WAN:
            if self.interface_lan not in self.interfaces_monitoradas or self.interface_wan not in self.interfaces_monitoradas:
                erros.append("No modo LAN_WAN, as interfaces LAN e WAN precisam estar nas interfaces monitoradas.")
        elif self.modo_captura == ModoCaptura.PERSONALIZADO:
            if not self.interfaces_monitoradas:
                erros.append("No modo PERSONALIZADO, pelo menos uma interface deve ser selecionada.")

        return erros

    def to_dict(self) -> dict[str, Any]:
        """Converte a configuração para formato JSON/Dict."""
        return _serializar_valor(self.__dict__)


@dataclass
class StatusServicoDados:
    """Descreve o status reportado de um daemon/serviço no sistema."""
    nome: str
    estado: EstadoServico = EstadoServico.DESCONHECIDO
    ativo: bool = False
    habilitado: bool = False
    instalado: bool = False
    pid: int | None = None
    detalhes: str = ""
    verificado_em: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Converte a representação do serviço para formato dicionário."""
        return _serializar_valor(self.__dict__)


@dataclass
class ProgressoTarefa:
    """Tracker unificado de progresso, mensagens e logs de uma tarefa do orquestrador."""
    tarefa_id: str
    tipo: TipoTarefaSuricata
    status: StatusEtapa = StatusEtapa.PENDENTE
    etapa_atual: str = ""
    progresso: int = 0
    mensagem: str = ""
    logs: list[LogExecucao] = field(default_factory=list)
    resultado: dict[str, Any] = field(default_factory=dict)
    erro: str = ""
    iniciado_em: datetime | None = None
    finalizado_em: datetime | None = None

    def __post_init__(self):
        """Assegura a normalização do progresso inicial."""
        self.progresso = max(0, min(100, self.progresso))

    def atualizar(self, progresso: int, etapa: str, mensagem: str, nivel: NivelLog = NivelLog.INFO) -> None:
        """Avança o progresso e adiciona um novo log de execução."""
        self.progresso = max(0, min(100, progresso))
        if self.status == StatusEtapa.PENDENTE:
            self.status = StatusEtapa.EXECUTANDO
        
        if self.iniciado_em is None:
            self.iniciado_em = datetime.now()
            
        self.etapa_atual = etapa
        self.mensagem = mensagem
        self.logs.append(LogExecucao(
            nivel=nivel,
            mensagem=mensagem,
            etapa=etapa
        ))

    def concluir(self, resultado: dict[str, Any] | None = None) -> None:
        """Define estado final da tarefa como SUCESSO e completa o progresso."""
        self.progresso = 100
        self.status = StatusEtapa.SUCESSO
        self.mensagem = "Tarefa concluída com sucesso."
        if resultado:
            self.resultado.update(resultado)
        self.finalizado_em = datetime.now()

    def falhar(self, mensagem: str, erro: str = "") -> None:
        """Encerra a tarefa prematuramente marcando falha severa."""
        self.status = StatusEtapa.ERRO
        self.mensagem = mensagem
        self.erro = erro
        self.finalizado_em = datetime.now()

    def cancelar(self, mensagem: str = "Tarefa cancelada.") -> None:
        """Aborta a tarefa atual."""
        self.status = StatusEtapa.CANCELADO
        self.mensagem = mensagem
        self.finalizado_em = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Converte o estado do tracker para um formato dicionário padronizado para a web."""
        return _serializar_valor(self.__dict__)