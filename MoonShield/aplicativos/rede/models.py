"""
MoonShield Network
==================

Modelos persistentes do módulo de rede.

Princípio principal:

    PostgreSQL = estado desejado / histórico / auditoria
    Linux      = estado real
    Agent      = responsável por sincronizar os dois

O Django nunca deve executar diretamente comandos privilegiados como:

    nmcli
    ip
    nft
    sysctl

Essas operações pertencem ao MoonShield-Agent.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


# =============================================================================
# MIXINS
# =============================================================================


class TimeStampedModel(models.Model):
    """
    Campos de auditoria temporal reutilizados pelos modelos de rede.
    """

    criado_em = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    atualizado_em = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        abstract = True


# =============================================================================
# INTERFACE DE REDE
# =============================================================================


class InterfaceRede(TimeStampedModel):
    """
    Representa uma interface física ou lógica conhecida pelo MoonShield.

    IMPORTANTE:

    `nome` representa o nome informado pelo Linux:

        enp0s3
        enp0s8
        ens18
        eth0
        bond0
        br0
        etc.

    Nenhum nome de interface deve ser hardcoded no sistema.

    Os campos de configuração representam o ESTADO DESEJADO.

    Os campos terminados em `_atual` representam o último ESTADO REAL
    informado pelo MoonShield-Agent.
    """

    # -------------------------------------------------------------------------
    # PAPEL
    # -------------------------------------------------------------------------

    class Papel(models.TextChoices):
        NAO_ATRIBUIDA = "unassigned", "Não atribuída"
        WAN = "wan", "WAN"
        LAN = "lan", "LAN"
        MGMT = "mgmt", "Gerenciamento"
        DMZ = "dmz", "DMZ"
        CUSTOM = "custom", "Personalizada"

    # -------------------------------------------------------------------------
    # MODO IPv4
    # -------------------------------------------------------------------------

    class ModoIPv4(models.TextChoices):
        DHCP = "dhcp", "DHCP"
        STATIC = "static", "Estático"
        DISABLED = "disabled", "Desativado"

    # -------------------------------------------------------------------------
    # ESTADO DO LINK
    # -------------------------------------------------------------------------

    class EstadoLink(models.TextChoices):
        DESCONHECIDO = "unknown", "Desconhecido"
        UP = "up", "UP"
        DOWN = "down", "DOWN"

    # -------------------------------------------------------------------------
    # BACKEND
    # -------------------------------------------------------------------------

    class Backend(models.TextChoices):
        DESCONHECIDO = "unknown", "Desconhecido"
        NETWORK_MANAGER = "networkmanager", "NetworkManager"
        SYSTEMD_NETWORKD = "networkd", "systemd-networkd"
        IFUPDOWN = "ifupdown", "ifupdown"
        RUNTIME = "runtime", "Runtime / iproute2"

    # -------------------------------------------------------------------------
    # IDENTIDADE
    # -------------------------------------------------------------------------

    nome = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Nome real da interface no Linux. Ex: enp0s3.",
    )

    descricao = models.CharField(
        max_length=120,
        blank=True,
        default="",
        help_text="Descrição amigável opcional.",
    )

    mac_address = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Último MAC address detectado pelo Agent.",
    )

    # -------------------------------------------------------------------------
    # FUNÇÃO NO MOONSHIELD
    # -------------------------------------------------------------------------

    papel = models.CharField(
        max_length=20,
        choices=Papel.choices,
        default=Papel.NAO_ATRIBUIDA,
        db_index=True,
    )

    principal = models.BooleanField(
        default=False,
        help_text=(
            "Define a interface principal daquele papel. "
            "Ex: WAN principal ou LAN principal."
        ),
    )

    habilitada = models.BooleanField(
        default=True,
    )

    acesso_gerenciamento = models.BooleanField(
        default=False,
        help_text=(
            "Permite que esta interface seja utilizada para acesso "
            "administrativo ao MoonShield."
        ),
    )

    # -------------------------------------------------------------------------
    # ESTADO DESEJADO — IPv4
    # -------------------------------------------------------------------------

    ipv4_modo = models.CharField(
        max_length=16,
        choices=ModoIPv4.choices,
        default=ModoIPv4.DHCP,
    )

    ipv4_endereco = models.GenericIPAddressField(
        protocol="IPv4",
        blank=True,
        null=True,
        help_text=(
            "IPv4 estático desejado. "
            "Deve permanecer vazio quando ipv4_modo=DHCP."
        ),
    )

    ipv4_prefixo = models.PositiveSmallIntegerField(
        blank=True,
        null=True,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(32),
        ],
        help_text="Prefixo IPv4. Ex: 24.",
    )

    gateway = models.GenericIPAddressField(
        protocol="IPv4",
        blank=True,
        null=True,
        help_text="Gateway desejado para esta interface.",
    )

    rota_padrao = models.BooleanField(
        default=False,
        help_text=(
            "Indica se esta interface deve fornecer rota default."
        ),
    )

    metrica = models.PositiveIntegerField(
        default=100,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(4_294_967_295),
        ],
    )

    mtu = models.PositiveIntegerField(
        default=1500,
        validators=[
            MinValueValidator(576),
            MaxValueValidator(65535),
        ],
    )

    # -------------------------------------------------------------------------
    # NETWORKMANAGER
    # -------------------------------------------------------------------------

    backend = models.CharField(
        max_length=24,
        choices=Backend.choices,
        default=Backend.DESCONHECIDO,
    )

    conexao_nome = models.CharField(
        max_length=160,
        blank=True,
        default="",
        help_text="Nome do profile/conexão do NetworkManager.",
    )

    conexao_uuid = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="UUID do profile NetworkManager, quando disponível.",
    )

    # -------------------------------------------------------------------------
    # ESTADO REAL — AGENT / LINUX
    # -------------------------------------------------------------------------

    estado_link = models.CharField(
        max_length=16,
        choices=EstadoLink.choices,
        default=EstadoLink.DESCONHECIDO,
    )

    carrier = models.BooleanField(
        blank=True,
        null=True,
        help_text="Estado físico do link quando detectável.",
    )

    ipv4_atual = models.GenericIPAddressField(
        protocol="IPv4",
        blank=True,
        null=True,
    )

    prefixo_atual = models.PositiveSmallIntegerField(
        blank=True,
        null=True,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(32),
        ],
    )

    gateway_atual = models.GenericIPAddressField(
        protocol="IPv4",
        blank=True,
        null=True,
    )

    metrica_atual = models.PositiveIntegerField(
        blank=True,
        null=True,
    )

    mtu_atual = models.PositiveIntegerField(
        blank=True,
        null=True,
    )

    # -------------------------------------------------------------------------
    # SINCRONIZAÇÃO
    # -------------------------------------------------------------------------

    sincronizada = models.BooleanField(
        default=False,
        db_index=True,
    )

    pendente = models.BooleanField(
        default=False,
        db_index=True,
    )

    ultimo_erro = models.TextField(
        blank=True,
        default="",
    )

    detectada_em = models.DateTimeField(
        blank=True,
        null=True,
        db_index=True,
        help_text="Última vez que o Agent confirmou esta interface.",
    )

    aplicada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    # -------------------------------------------------------------------------
    # META
    # -------------------------------------------------------------------------

    class Meta:
        ordering = [
            "papel",
            "-principal",
            "nome",
        ]

        verbose_name = "Interface de rede"
        verbose_name_plural = "Interfaces de rede"

        indexes = [
            models.Index(
                fields=["papel", "principal"],
                name="rede_iface_papel_princ_idx",
            ),
            models.Index(
                fields=["sincronizada", "pendente"],
                name="rede_iface_sync_idx",
            ),
        ]

    def __str__(self) -> str:
        if self.papel == self.Papel.NAO_ATRIBUIDA:
            return self.nome

        return f"{self.nome} · {self.get_papel_display()}"

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    @property
    def possui_ipv4(self) -> bool:
        return bool(self.ipv4_atual)

    @property
    def possui_configuracao_estatica(self) -> bool:
        return (
            self.ipv4_modo == self.ModoIPv4.STATIC
            and bool(self.ipv4_endereco)
            and self.ipv4_prefixo is not None
        )

    @property
    def online(self) -> bool:
        return self.estado_link == self.EstadoLink.UP

    def marcar_detectada(self) -> None:
        self.detectada_em = timezone.now()

    def marcar_erro(self, mensagem: str) -> None:
        self.sincronizada = False
        self.pendente = True
        self.ultimo_erro = str(mensagem or "")

    def marcar_sincronizada(self) -> None:
        self.sincronizada = True
        self.pendente = False
        self.ultimo_erro = ""
        self.aplicada_em = timezone.now()


# =============================================================================
# CONFIGURAÇÃO GLOBAL DE ROTEAMENTO
# =============================================================================


class ConfiguracaoRoteamento(TimeStampedModel):
    """
    Configuração global do roteamento do MoonShield.

    Para V1 teremos normalmente apenas um registro.
    """

    ipv4_forward = models.BooleanField(
        default=False,
        help_text="Habilita net.ipv4.ip_forward.",
    )

    gerenciamento_automatico_rota_default = models.BooleanField(
        default=True,
        help_text=(
            "Permite ao MoonShield gerenciar a rota padrão "
            "através da WAN principal."
        ),
    )

    rollback_automatico = models.BooleanField(
        default=True,
    )

    tempo_confirmacao = models.PositiveSmallIntegerField(
        default=60,
        validators=[
            MinValueValidator(15),
            MaxValueValidator(600),
        ],
        help_text=(
            "Tempo em segundos para confirmar uma alteração "
            "antes do rollback automático."
        ),
    )

    ativo = models.BooleanField(
        default=True,
    )

    class Meta:
        verbose_name = "Configuração de roteamento"
        verbose_name_plural = "Configurações de roteamento"

    def __str__(self) -> str:
        estado = "ON" if self.ipv4_forward else "OFF"

        return f"Roteamento IPv4 · {estado}"

    @classmethod
    def atual(cls):
        """
        Retorna a configuração principal.

        Enquanto o MoonShield trabalhar como appliance único,
        existe apenas uma configuração global.
        """

        obj, _ = cls.objects.get_or_create(
            pk=1,
        )

        return obj


# =============================================================================
# ROTAS ESTÁTICAS
# =============================================================================


class RotaEstatica(TimeStampedModel):
    """
    Rotas adicionais administradas pelo MoonShield.

    A rota padrão principal não precisa ser criada aqui.
    Ela é definida pela interface marcada com `rota_padrao=True`.
    """

    nome = models.CharField(
        max_length=120,
        blank=True,
        default="",
    )

    destino = models.CharField(
        max_length=64,
        help_text="Rede destino em CIDR. Ex: 10.20.0.0/16.",
    )

    gateway = models.GenericIPAddressField(
        protocol="IPv4",
        blank=True,
        null=True,
    )

    interface = models.ForeignKey(
        InterfaceRede,
        on_delete=models.PROTECT,
        related_name="rotas_estaticas",
        blank=True,
        null=True,
    )

    metrica = models.PositiveIntegerField(
        default=100,
    )

    ativa = models.BooleanField(
        default=True,
    )

    sincronizada = models.BooleanField(
        default=False,
    )

    pendente = models.BooleanField(
        default=True,
    )

    ultimo_erro = models.TextField(
        blank=True,
        default="",
    )

    class Meta:
        ordering = [
            "metrica",
            "destino",
        ]

        verbose_name = "Rota estática"
        verbose_name_plural = "Rotas estáticas"

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "destino",
                    "gateway",
                    "interface",
                    "metrica",
                ],
                name="rede_rota_unica",
            ),
        ]

    def __str__(self) -> str:
        partes = [
            self.destino,
        ]

        if self.gateway:
            partes.append(f"via {self.gateway}")

        if self.interface:
            partes.append(f"dev {self.interface.nome}")

        return " ".join(partes)


# =============================================================================
# NAT
# =============================================================================


class RegraNat(TimeStampedModel):
    """
    Regras NAT administradas pelo módulo de Rede.

    IMPORTANTE:

    Este modelo controla NAT/MASQUERADE.

    Regras ALLOW/DENY pertencem ao app Firewall.
    """

    class Tipo(models.TextChoices):
        MASQUERADE = "masquerade", "Masquerade"

    nome = models.CharField(
        max_length=120,
        default="NAT LAN → WAN",
    )

    tipo = models.CharField(
        max_length=20,
        choices=Tipo.choices,
        default=Tipo.MASQUERADE,
    )

    interface_origem = models.ForeignKey(
        InterfaceRede,
        on_delete=models.PROTECT,
        related_name="regras_nat_origem",
        help_text="Normalmente uma interface LAN.",
    )

    interface_saida = models.ForeignKey(
        InterfaceRede,
        on_delete=models.PROTECT,
        related_name="regras_nat_saida",
        help_text="Normalmente a WAN.",
    )

    origem_cidr = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text=(
            "Opcional. Se vazio, o Agent poderá utilizar "
            "a rede da interface de origem."
        ),
    )

    ativa = models.BooleanField(
        default=True,
    )

    prioridade = models.PositiveIntegerField(
        default=100,
    )

    sincronizada = models.BooleanField(
        default=False,
    )

    pendente = models.BooleanField(
        default=True,
    )

    ultimo_erro = models.TextField(
        blank=True,
        default="",
    )

    aplicada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    class Meta:
        ordering = [
            "prioridade",
            "id",
        ]

        verbose_name = "Regra NAT"
        verbose_name_plural = "Regras NAT"

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "interface_origem",
                    "interface_saida",
                    "tipo",
                ],
                name="rede_nat_interface_unica",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.interface_origem.nome} → "
            f"{self.interface_saida.nome} · "
            f"{self.get_tipo_display()}"
        )


# =============================================================================
# SNAPSHOT
# =============================================================================


class SnapshotRede(TimeStampedModel):
    """
    Snapshot completo do estado da rede.

    Deve ser criado ANTES de alterações potencialmente destrutivas.

    O conteúdo é propositalmente JSON para permitir armazenar:

        interfaces
        profiles NetworkManager
        endereços
        rotas
        gateway
        ip_forward
        NAT
        backend
        demais metadados

    sem obrigar uma migration para cada detalhe do Linux.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    origem = models.CharField(
        max_length=64,
        default="moonshield-agent",
    )

    backend = models.CharField(
        max_length=32,
        blank=True,
        default="",
    )

    dados = models.JSONField(
        default=dict,
    )

    automatico = models.BooleanField(
        default=True,
    )

    valido = models.BooleanField(
        default=True,
    )

    observacao = models.TextField(
        blank=True,
        default="",
    )

    criado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="snapshots_rede_criados",
    )

    class Meta:
        ordering = [
            "-criado_em",
        ]

        verbose_name = "Snapshot de rede"
        verbose_name_plural = "Snapshots de rede"

    def __str__(self) -> str:
        return f"Snapshot {self.id} · {self.criado_em:%d/%m/%Y %H:%M:%S}"


# =============================================================================
# ALTERAÇÃO DE REDE
# =============================================================================


class AlteracaoRede(TimeStampedModel):
    """
    Representa uma operação de alteração da rede.

    Fluxo esperado:

        CRIADA
          ↓
        VALIDANDO
          ↓
        APLICANDO
          ↓
        AGUARDANDO_CONFIRMACAO
          ↓
        CONFIRMADA

    Se a confirmação não ocorrer:

        AGUARDANDO_CONFIRMACAO
          ↓
        ROLLBACK
          ↓
        REVERTIDA

    Em falha:

        FALHOU
    """

    class Status(models.TextChoices):
        CRIADA = "created", "Criada"
        VALIDANDO = "validating", "Validando"
        APLICANDO = "applying", "Aplicando"
        AGUARDANDO_CONFIRMACAO = (
            "waiting_confirmation",
            "Aguardando confirmação",
        )
        CONFIRMADA = "confirmed", "Confirmada"
        ROLLBACK = "rollback", "Rollback em andamento"
        REVERTIDA = "reverted", "Revertida"
        FALHOU = "failed", "Falhou"
        CANCELADA = "cancelled", "Cancelada"

    class Tipo(models.TextChoices):
        INTERFACE = "interface", "Interface"
        ROTEAMENTO = "routing", "Roteamento"
        NAT = "nat", "NAT"
        ROTA = "route", "Rota"
        GERAL = "general", "Configuração geral"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    tipo = models.CharField(
        max_length=24,
        choices=Tipo.choices,
        default=Tipo.GERAL,
        db_index=True,
    )

    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.CRIADA,
        db_index=True,
    )

    titulo = models.CharField(
        max_length=160,
        blank=True,
        default="",
    )

    descricao = models.TextField(
        blank=True,
        default="",
    )

    # -------------------------------------------------------------------------
    # CONFIGURAÇÃO
    # -------------------------------------------------------------------------

    configuracao_solicitada = models.JSONField(
        default=dict,
        help_text="Payload solicitado pelo Django.",
    )

    resultado_agent = models.JSONField(
        default=dict,
        blank=True,
        help_text="Último resultado estruturado retornado pelo Agent.",
    )

    # -------------------------------------------------------------------------
    # SNAPSHOTS
    # -------------------------------------------------------------------------

    snapshot_anterior = models.ForeignKey(
        SnapshotRede,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="alteracoes_origem",
    )

    snapshot_posterior = models.ForeignKey(
        SnapshotRede,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="alteracoes_resultado",
    )

    # -------------------------------------------------------------------------
    # CONFIRMAÇÃO / ROLLBACK
    # -------------------------------------------------------------------------

    requer_confirmacao = models.BooleanField(
        default=True,
    )

    expira_em = models.DateTimeField(
        blank=True,
        null=True,
        db_index=True,
    )

    iniciada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    aplicada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    confirmada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    rollback_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    finalizada_em = models.DateTimeField(
        blank=True,
        null=True,
    )

    # -------------------------------------------------------------------------
    # ERROS / LOG
    # -------------------------------------------------------------------------

    erro = models.TextField(
        blank=True,
        default="",
    )

    log = models.TextField(
        blank=True,
        default="",
    )

    # -------------------------------------------------------------------------
    # USUÁRIO
    # -------------------------------------------------------------------------

    solicitado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="alteracoes_rede_solicitadas",
    )

    confirmado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="alteracoes_rede_confirmadas",
    )

    # -------------------------------------------------------------------------
    # META
    # -------------------------------------------------------------------------

    class Meta:
        ordering = [
            "-criado_em",
        ]

        verbose_name = "Alteração de rede"
        verbose_name_plural = "Alterações de rede"

        indexes = [
            models.Index(
                fields=["status", "-criado_em"],
                name="rede_alt_status_data_idx",
            ),
            models.Index(
                fields=["tipo", "-criado_em"],
                name="rede_alt_tipo_data_idx",
            ),
        ]

    def __str__(self) -> str:
        titulo = self.titulo or self.get_tipo_display()

        return f"{titulo} · {self.get_status_display()}"

    # -------------------------------------------------------------------------
    # STATUS HELPERS
    # -------------------------------------------------------------------------

    @property
    def aguardando_confirmacao(self) -> bool:
        return (
            self.status
            == self.Status.AGUARDANDO_CONFIRMACAO
        )

    @property
    def expirou(self) -> bool:
        if not self.expira_em:
            return False

        return timezone.now() >= self.expira_em

    @property
    def finalizada(self) -> bool:
        return self.status in {
            self.Status.CONFIRMADA,
            self.Status.REVERTIDA,
            self.Status.FALHOU,
            self.Status.CANCELADA,
        }

    def adicionar_log(self, mensagem: str) -> None:
        """
        Acrescenta uma linha ao log da alteração.
        """

        agora = timezone.localtime().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        linha = f"[{agora}] {mensagem}"

        if self.log:
            self.log += "\n"

        self.log += linha

    def marcar_aplicada(
        self,
        expira_em=None,
    ) -> None:
        agora = timezone.now()

        self.aplicada_em = agora

        if self.requer_confirmacao:
            self.status = (
                self.Status.AGUARDANDO_CONFIRMACAO
            )
            self.expira_em = expira_em
        else:
            self.status = self.Status.CONFIRMADA
            self.confirmada_em = agora
            self.finalizada_em = agora

    def marcar_confirmada(
        self,
        usuario=None,
    ) -> None:
        agora = timezone.now()

        self.status = self.Status.CONFIRMADA
        self.confirmada_em = agora
        self.finalizada_em = agora

        if usuario is not None:
            self.confirmado_por = usuario

    def marcar_falha(
        self,
        mensagem: str,
    ) -> None:
        self.status = self.Status.FALHOU
        self.erro = str(mensagem or "")
        self.finalizada_em = timezone.now()

        self.adicionar_log(
            f"FALHA: {self.erro}"
        )


# =============================================================================
# EVENTO / AUDITORIA
# =============================================================================


class EventoRede(TimeStampedModel):
    """
    Auditoria operacional do módulo de Rede.

    Não é o log bruto do Linux.

    Registra eventos importantes para o painel e histórico:

        interface alterada
        IP alterado
        WAN definida
        LAN definida
        NAT aplicado
        rollback executado
        diagnóstico executado
        Agent perdeu conexão
    """

    class Nivel(models.TextChoices):
        INFO = "info", "Informação"
        SUCCESS = "success", "Sucesso"
        WARNING = "warning", "Aviso"
        ERROR = "error", "Erro"

    nivel = models.CharField(
        max_length=16,
        choices=Nivel.choices,
        default=Nivel.INFO,
        db_index=True,
    )

    codigo = models.CharField(
        max_length=80,
        blank=True,
        default="",
        db_index=True,
    )

    titulo = models.CharField(
        max_length=180,
    )

    mensagem = models.TextField(
        blank=True,
        default="",
    )

    dados = models.JSONField(
        default=dict,
        blank=True,
    )

    interface = models.ForeignKey(
        InterfaceRede,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="eventos",
    )

    alteracao = models.ForeignKey(
        AlteracaoRede,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="eventos",
    )

    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="eventos_rede",
    )

    class Meta:
        ordering = [
            "-criado_em",
        ]

        verbose_name = "Evento de rede"
        verbose_name_plural = "Eventos de rede"

        indexes = [
            models.Index(
                fields=["nivel", "-criado_em"],
                name="rede_event_nivel_data_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.get_nivel_display()} · {self.titulo}"