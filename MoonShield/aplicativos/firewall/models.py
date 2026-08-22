"""
MoonShield Platform — Firewall / Models
=======================================

Modelos persistentes do módulo de Firewall.

Arquitetura atual:

    Django
      ├── configuração/orquestração
      ├── regras desejadas
      ├── auditoria/eventos
      ├── tarefas
      └── estado consolidado
             ↓ IPC local
    MoonShield-Agent
             ↓
          nftables

Observações importantes:
- O Firewall NÃO depende mais de Sensor/HTTP para aplicar regras.
- `EventoFirewall.sensor` permanece nullable apenas por compatibilidade
  histórica com eventos antigos.
- `pendente`/`sincronizada` agora representam sincronização entre o estado
  desejado no Django e o estado efetivamente aplicado pelo Agent/nftables.
"""

from __future__ import annotations

import hashlib

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


# =============================================================================
# CONFIGURAÇÃO DO FIREWALL
# =============================================================================

class ConfiguracaoFirewall(models.Model):
    """
    Singleton com o estado/configuração conhecida pelo Django.

    A fonte de verdade técnica continua sendo o MoonShield-Agent.
    Este model guarda configuração de negócio, onboarding e último estado
    observado para UI/auditoria.
    """

    ativo = models.BooleanField(
        default=False,
        db_index=True,
    )

    onboarding_concluido = models.BooleanField(
        default=False,
    )

    instalacao_concluida = models.BooleanField(
        default=False,
    )

    # Topologia
    interface_wan = models.CharField(
        max_length=32,
        blank=True,
    )

    interface_lan = models.CharField(
        max_length=32,
        blank=True,
    )

    interface_mgmt = models.CharField(
        max_length=32,
        blank=True,
    )

    home_net = models.CharField(
        max_length=64,
        blank=True,
    )

    # Estado técnico consolidado
    nftables_instalado = models.BooleanField(
        default=False,
    )

    tabela_instalada = models.BooleanField(
        default=False,
    )

    chains_ok = models.BooleanField(
        default=False,
    )

    agent_ativo = models.BooleanField(
        default=False,
    )

    monitor_ativo = models.BooleanField(
        default=False,
    )

    persistencia_ok = models.BooleanField(
        default=False,
    )

    operacional = models.BooleanField(
        default=False,
        db_index=True,
    )

    # Versões
    nftables_versao = models.CharField(
        max_length=100,
        blank=True,
    )

    agent_versao = models.CharField(
        max_length=50,
        blank=True,
    )

    # Diagnóstico / cache de status
    ultimo_status = models.JSONField(
        default=dict,
        blank=True,
    )

    ultimo_diagnostico = models.JSONField(
        default=dict,
        blank=True,
    )

    ultimo_erro = models.TextField(
        blank=True,
    )

    ultimo_healthcheck_em = models.DateTimeField(
        null=True,
        blank=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    @classmethod
    def get_solo(cls) -> "ConfiguracaoFirewall":
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def atualizar_status(
        self,
        status: dict,
        *,
        erro: str = "",
    ) -> None:
        """
        Atualiza o snapshot local a partir do contrato de firewall_status.py.
        """
        status = status or {}

        self.agent_ativo = bool(
            status.get("agent_ativo")
            or status.get("agent_disponivel")
        )

        self.nftables_instalado = bool(
            status.get("nftables_instalado")
        )

        self.tabela_instalada = bool(
            status.get("tabela_instalada")
            or status.get("ativo")
        )

        self.chains_ok = bool(
            status.get("chains_ok")
        )

        self.operacional = bool(
            status.get("operacional")
        )

        self.ativo = bool(
            status.get("ativo")
            or status.get("operacional")
        )

        self.interface_wan = str(
            status.get("interface_wan")
            or self.interface_wan
            or ""
        )[:32]

        self.interface_lan = str(
            status.get("interface_lan")
            or self.interface_lan
            or ""
        )[:32]

        self.interface_mgmt = str(
            status.get("interface_mgmt")
            or self.interface_mgmt
            or ""
        )[:32]

        self.home_net = str(
            status.get("home_net")
            or self.home_net
            or ""
        )[:64]

        self.nftables_versao = str(
            status.get("nftables_versao")
            or ""
        )[:100]

        agent = status.get("agent") or {}
        if isinstance(agent, dict):
            self.agent_versao = str(
                agent.get("versao")
                or agent.get("ipc_versao")
                or ""
            )[:50]

        self.ultimo_status = status
        self.ultimo_erro = str(erro or "")
        self.ultimo_healthcheck_em = timezone.now()

        self.save()

    def __str__(self) -> str:
        return (
            "Firewall — Operacional"
            if self.operacional
            else "Firewall — Não operacional"
        )

    class Meta:
        verbose_name = "Configuração do Firewall"
        verbose_name_plural = "Configuração do Firewall"


# =============================================================================
# TAREFAS
# =============================================================================

class TarefaFirewall(models.Model):
    """
    Registra operações do Firewall iniciadas pelo Django.

    O processamento poderá ser feito por command/worker sem deixar a request
    HTTP presa durante instalação, reparo ou aplicação longa.
    """

    class Tipo(models.TextChoices):
        INSTALAR = "instalar", "Instalar"
        REPARAR = "reparar", "Reparar"
        APLICAR_REGRAS = "aplicar_regras", "Aplicar regras"
        ROLLBACK = "rollback", "Rollback"
        DIAGNOSTICAR = "diagnosticar", "Diagnosticar"
        DESINSTALAR = "desinstalar", "Desinstalar"

    class Status(models.TextChoices):
        PENDENTE = "pendente", "Pendente"
        EXECUTANDO = "executando", "Executando"
        SUCESSO = "sucesso", "Sucesso"
        ERRO = "erro", "Erro"
        CANCELADA = "cancelada", "Cancelada"

    tipo = models.CharField(
        max_length=30,
        choices=Tipo.choices,
        db_index=True,
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDENTE,
        db_index=True,
    )

    progresso = models.PositiveSmallIntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
    )

    etapa_atual = models.CharField(
        max_length=150,
        blank=True,
    )

    mensagem = models.CharField(
        max_length=500,
        blank=True,
    )

    payload = models.JSONField(
        default=dict,
        blank=True,
    )

    resultado = models.JSONField(
        default=dict,
        blank=True,
    )

    logs = models.JSONField(
        default=list,
        blank=True,
    )

    erro = models.TextField(
        blank=True,
    )

    snapshot_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
    )

    iniciado_em = models.DateTimeField(
        null=True,
        blank=True,
    )

    finalizado_em = models.DateTimeField(
        null=True,
        blank=True,
    )

    duracao_segundos = models.FloatField(
        null=True,
        blank=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def iniciar(
        self,
        *,
        etapa: str = "",
        mensagem: str = "",
    ) -> None:
        self.status = self.Status.EXECUTANDO
        self.progresso = max(self.progresso, 1)
        self.etapa_atual = etapa[:150]
        self.mensagem = mensagem[:500]
        self.iniciado_em = self.iniciado_em or timezone.now()
        self.finalizado_em = None
        self.erro = ""

        self.save(
            update_fields=[
                "status",
                "progresso",
                "etapa_atual",
                "mensagem",
                "iniciado_em",
                "finalizado_em",
                "erro",
                "atualizado_em",
            ]
        )

    def atualizar_progresso(
        self,
        progresso: int,
        *,
        etapa: str | None = None,
        mensagem: str | None = None,
    ) -> None:
        self.progresso = max(
            0,
            min(
                100,
                int(progresso),
            ),
        )

        campos = [
            "progresso",
            "atualizado_em",
        ]

        if etapa is not None:
            self.etapa_atual = str(etapa)[:150]
            campos.append("etapa_atual")

        if mensagem is not None:
            self.mensagem = str(mensagem)[:500]
            campos.append("mensagem")

        self.save(
            update_fields=campos
        )

    def adicionar_log(
        self,
        mensagem: str,
        *,
        nivel: str = "info",
    ) -> None:
        atual = list(
            self.logs
            if isinstance(self.logs, list)
            else []
        )

        atual.append(
            {
                "timestamp": timezone.now().isoformat(),
                "nivel": str(nivel or "info"),
                "mensagem": str(mensagem),
            }
        )

        # Proteção para o JSONField não crescer indefinidamente.
        self.logs = atual[-500:]

        self.save(
            update_fields=[
                "logs",
                "atualizado_em",
            ]
        )

    def finalizar_sucesso(
        self,
        *,
        resultado: dict | None = None,
        mensagem: str = "",
    ) -> None:
        agora = timezone.now()

        self.status = self.Status.SUCESSO
        self.progresso = 100
        self.mensagem = mensagem[:500]
        self.resultado = resultado or {}
        self.erro = ""
        self.finalizado_em = agora

        if self.iniciado_em:
            self.duracao_segundos = max(
                0.0,
                (agora - self.iniciado_em).total_seconds(),
            )

        self.save()

    def finalizar_erro(
        self,
        erro: str,
        *,
        resultado: dict | None = None,
        mensagem: str = "",
    ) -> None:
        agora = timezone.now()

        self.status = self.Status.ERRO
        self.mensagem = mensagem[:500]
        self.resultado = resultado or {}
        self.erro = str(erro)
        self.finalizado_em = agora

        if self.iniciado_em:
            self.duracao_segundos = max(
                0.0,
                (agora - self.iniciado_em).total_seconds(),
            )

        self.save()

    @property
    def concluida(self) -> bool:
        return self.status in {
            self.Status.SUCESSO,
            self.Status.ERRO,
            self.Status.CANCELADA,
        }

    def __str__(self) -> str:
        return f"{self.get_tipo_display()} — {self.get_status_display()}"

    class Meta:
        ordering = [
            "-criado_em",
        ]
        verbose_name = "Tarefa do Firewall"
        verbose_name_plural = "Tarefas do Firewall"
        indexes = [
            models.Index(
                fields=["status", "criado_em"],
                name="idx_fw_task_status_dt",
            ),
            models.Index(
                fields=["tipo", "status"],
                name="idx_fw_task_tipo_status",
            ),
        ]


# =============================================================================
# REGRAS
# =============================================================================

class RegraFirewall(models.Model):

    class Acao(models.TextChoices):
        ALLOW = "allow", "ALLOW"
        DENY = "deny", "DENY"

    class Interface(models.TextChoices):
        WAN = "WAN", "WAN"
        LAN = "LAN", "LAN"
        MGMT = "MGMT", "MGMT"
        VPN = "VPN", "VPN"
        ANY = "any", "ANY"

    class Direcao(models.TextChoices):
        IN = "in", "IN"
        OUT = "out", "OUT"
        FORWARD = "forward", "FORWARD"
        BOTH = "both", "AMBOS"

    class Protocolo(models.TextChoices):
        TCP = "TCP", "TCP"
        UDP = "UDP", "UDP"
        ICMP = "ICMP", "ICMP"
        ICMPV6 = "ICMPV6", "ICMPv6"
        ANY = "any", "ANY"

    priority = models.IntegerField(
        default=100,
        db_index=True,
    )

    action = models.CharField(
        max_length=10,
        choices=Acao.choices,
        default=Acao.DENY,
    )

    iface = models.CharField(
        max_length=32,
        choices=Interface.choices,
        default=Interface.ANY,
    )

    dir = models.CharField(
        max_length=10,
        choices=Direcao.choices,
        default=Direcao.IN,
    )

    proto = models.CharField(
        max_length=10,
        choices=Protocolo.choices,
        default=Protocolo.TCP,
    )

    # 255 permite IPv6, CIDR e listas futuras.
    src = models.CharField(
        max_length=255,
        default="any",
    )

    dst = models.CharField(
        max_length=255,
        default="any",
    )

    port = models.CharField(
        max_length=255,
        default="any",
    )

    desc = models.CharField(
        max_length=255,
        blank=True,
    )

    enabled = models.BooleanField(
        default=True,
        db_index=True,
    )

    log = models.BooleanField(
        default=True,
    )

    # -------------------------------------------------------------------------
    # Sincronização local Django ↔ Agent/nftables
    # -------------------------------------------------------------------------
    # pendente=True:
    #   estado desejado mudou e ainda precisa ser aplicado no nftables.
    #
    # sincronizada=True:
    #   o Agent confirmou que o conjunto correspondente foi aplicado.
    #
    # deletado=True:
    #   soft-delete. A regra permanece no DB até o Agent aplicar com sucesso
    #   um conjunto que já não contém a regra.
    # -------------------------------------------------------------------------

    pendente = models.BooleanField(
        default=True,
        db_index=True,
    )

    sincronizada = models.BooleanField(
        default=False,
        db_index=True,
    )

    deletado = models.BooleanField(
        default=False,
        db_index=True,
    )

    ultimo_erro = models.CharField(
        max_length=500,
        blank=True,
    )

    sincronizada_em = models.DateTimeField(
        null=True,
        blank=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def marcar_pendente(
        self,
        *,
        erro: str = "",
    ) -> None:
        self.pendente = True
        self.sincronizada = False
        self.sincronizada_em = None
        self.ultimo_erro = str(erro or "")[:500]

        self.save(
            update_fields=[
                "pendente",
                "sincronizada",
                "sincronizada_em",
                "ultimo_erro",
                "atualizado_em",
            ]
        )

    def marcar_sincronizada(self) -> None:
        self.pendente = False
        self.sincronizada = True
        self.sincronizada_em = timezone.now()
        self.ultimo_erro = ""

        self.save(
            update_fields=[
                "pendente",
                "sincronizada",
                "sincronizada_em",
                "ultimo_erro",
                "atualizado_em",
            ]
        )

    def marcar_deletada(self) -> None:
        self.deletado = True
        self.pendente = True
        self.sincronizada = False
        self.sincronizada_em = None

        self.save(
            update_fields=[
                "deletado",
                "pendente",
                "sincronizada",
                "sincronizada_em",
                "atualizado_em",
            ]
        )

    def __str__(self) -> str:
        if self.deletado:
            status = "DELETADA"
        elif self.sincronizada:
            status = "APLICADA"
        elif self.pendente:
            status = "PENDENTE"
        else:
            status = "NÃO SINCRONIZADA"

        return (
            f"[{self.priority}] {self.action.upper()} "
            f"{self.iface} {self.src} -> {self.dst}:{self.port} "
            f"[{status}]"
        )

    class Meta:
        ordering = [
            "priority",
            "id",
        ]
        verbose_name = "Regra de Firewall"
        verbose_name_plural = "Regras de Firewall"
        indexes = [
            models.Index(
                fields=["enabled", "priority"],
                name="idx_fw_rule_ativo_prio",
            ),
            models.Index(
                fields=["pendente", "sincronizada"],
                name="idx_fw_rule_sync",
            ),
            models.Index(
                fields=["deletado"],
                name="idx_fw_rule_deletado",
            ),
        ]


# =============================================================================
# NAT / PORT FORWARD
# =============================================================================

class NatEntry(models.Model):

    class Interface(models.TextChoices):
        WAN = "WAN", "WAN"
        LAN = "LAN", "LAN"
        VPN = "VPN", "VPN"

    class Protocolo(models.TextChoices):
        TCP = "TCP", "TCP"
        UDP = "UDP", "UDP"
        ANY = "any", "ANY"

    name = models.CharField(
        max_length=100,
    )

    iface = models.CharField(
        max_length=10,
        choices=Interface.choices,
        default=Interface.WAN,
    )

    wan_port = models.CharField(
        max_length=32,
    )

    lan_ip = models.GenericIPAddressField()

    lan_port = models.CharField(
        max_length=32,
    )

    proto = models.CharField(
        max_length=10,
        choices=Protocolo.choices,
        default=Protocolo.TCP,
    )

    enabled = models.BooleanField(
        default=True,
        db_index=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def __str__(self) -> str:
        return (
            f"{self.name}: {self.iface}:{self.wan_port} "
            f"-> {self.lan_ip}:{self.lan_port}/{self.proto}"
        )

    class Meta:
        ordering = [
            "name",
        ]
        verbose_name = "NAT / Port Forward"
        verbose_name_plural = "NAT / Port Forwards"
        indexes = [
            models.Index(
                fields=["enabled", "iface"],
                name="idx_fw_nat_enabled_if",
            ),
        ]


# =============================================================================
# BLOCKLIST
# =============================================================================

class BlocklistEntry(models.Model):

    class Source(models.TextChoices):
        MANUAL = "Manual", "Manual"
        AUTO = "Auto", "Auto"
        SOC = "SOC", "SOC"

    ip = models.CharField(
        max_length=50,
        db_index=True,
    )

    reason = models.CharField(
        max_length=255,
        blank=True,
    )

    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.MANUAL,
        db_index=True,
    )

    expires = models.CharField(
        max_length=20,
        default="∞",
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def __str__(self) -> str:
        return f"BLOCK {self.ip}"

    class Meta:
        ordering = [
            "-criado_em",
        ]
        verbose_name = "Blocklist"
        verbose_name_plural = "Blocklist"
        indexes = [
            models.Index(
                fields=["source", "criado_em"],
                name="idx_fw_block_src_dt",
            ),
        ]


# =============================================================================
# ALLOWLIST
# =============================================================================

class AllowlistEntry(models.Model):

    ip = models.CharField(
        max_length=255,
        db_index=True,
    )

    reason = models.CharField(
        max_length=255,
        blank=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def __str__(self) -> str:
        return f"ALLOW {self.ip}"

    class Meta:
        ordering = [
            "-criado_em",
        ]
        verbose_name = "Allowlist"
        verbose_name_plural = "Allowlist"


# =============================================================================
# GEOBLOCK
# =============================================================================

class GeoblockEntry(models.Model):

    class Direcao(models.TextChoices):
        IN = "IN", "IN"
        OUT = "OUT", "OUT"
        BOTH = "BOTH", "BOTH"

    country = models.CharField(
        max_length=100,
    )

    code = models.CharField(
        max_length=5,
        unique=True,
        db_index=True,
    )

    dir = models.CharField(
        max_length=5,
        choices=Direcao.choices,
        default=Direcao.IN,
    )

    enabled = models.BooleanField(
        default=True,
        db_index=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    def save(self, *args, **kwargs):
        if self.code:
            self.code = self.code.strip().upper()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"GEO {self.code} ({self.country})"

    class Meta:
        ordering = [
            "country",
        ]
        verbose_name = "GeoBlock"
        verbose_name_plural = "GeoBlock"
        indexes = [
            models.Index(
                fields=["enabled", "dir"],
                name="idx_fw_geo_enabled_dir",
            ),
        ]


# =============================================================================
# EVENTOS DO FIREWALL
# =============================================================================

class EventoFirewall(models.Model):

    class Acao(models.TextChoices):
        ALLOW = "ALLOW", "Allow"
        DROP = "DROP", "Drop"
        DENY = "DENY", "Deny"
        LOG = "LOG", "Log"

    # -------------------------------------------------------------------------
    # LEGADO
    # -------------------------------------------------------------------------
    # Eventos novos do Firewall local usam sensor=None.
    # O FK permanece temporariamente para preservar registros históricos.
    # -------------------------------------------------------------------------
    sensor = models.ForeignKey(
        "incidentes.Sensor",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="eventos_firewall",
    )

    timestamp = models.DateTimeField(
        db_index=True,
    )

    acao = models.CharField(
        max_length=10,
        choices=Acao.choices,
        default=Acao.ALLOW,
        db_index=True,
    )

    chain = models.CharField(
        max_length=30,
        blank=True,
        db_index=True,
    )

    proto = models.CharField(
        max_length=15,
        blank=True,
        db_index=True,
    )

    src_ip = models.GenericIPAddressField(
        db_index=True,
    )

    src_port = models.IntegerField(
        null=True,
        blank=True,
    )

    dst_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    dst_port = models.IntegerField(
        null=True,
        blank=True,
    )

    iface = models.CharField(
        max_length=32,
        blank=True,
        db_index=True,
    )

    iface_saida = models.CharField(
        max_length=32,
        blank=True,
    )

    tamanho = models.IntegerField(
        null=True,
        blank=True,
    )

    ttl = models.IntegerField(
        null=True,
        blank=True,
    )

    flags_tcp = models.CharField(
        max_length=100,
        blank=True,
    )

    prefixo = models.CharField(
        max_length=30,
        blank=True,
        db_index=True,
    )

    event_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
    )

    raw_json = models.JSONField(
        null=True,
        blank=True,
    )

    criado_em = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    @staticmethod
    def calcular_hash(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        timestamp,
        prefixo,
    ) -> str:
        ts = (
            timestamp.strftime("%Y%m%d%H%M%S%f")
            if hasattr(timestamp, "strftime")
            else str(timestamp)
        )

        raw = (
            f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|"
            f"{proto}|{ts}|{prefixo}"
        )

        return hashlib.sha256(
            raw.encode("utf-8")
        ).hexdigest()

    def __str__(self) -> str:
        return (
            f"[{self.acao}] "
            f"{self.src_ip}:{self.src_port or '?'} -> "
            f"{self.dst_ip or '?'}:{self.dst_port or '?'} "
            f"({self.proto or 'ANY'})"
        )

    class Meta:
        ordering = [
            "-timestamp",
        ]
        verbose_name = "Evento de Firewall"
        verbose_name_plural = "Eventos de Firewall"
        indexes = [
            models.Index(
                fields=["src_ip", "timestamp"],
                name="idx_fw_srcip_ts",
            ),
            models.Index(
                fields=["acao", "timestamp"],
                name="idx_fw_acao_ts",
            ),
            models.Index(
                fields=["dst_port", "timestamp"],
                name="idx_fw_dstport_ts",
            ),
            models.Index(
                fields=["iface", "timestamp"],
                name="idx_fw_iface_ts",
            ),
        ]
