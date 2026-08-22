"""
MoonShield Network
==================

Orquestrador de alterações de Rede.

Este é o ponto central do Control Plane para operações que podem
alterar conectividade do appliance.

Fluxo seguro:

    PostgreSQL
        ↓
    cria AlteracaoRede
        ↓
    valida configuração desejada
        ↓
    solicita aplicação segura ao Agent
        ↓
    Agent cria snapshot
        ↓
    Agent ARMA rollback automático
        ↓
    Agent aplica alteração
        ↓
    Django registra:
        AGUARDANDO_CONFIRMACAO
        ↓
    usuário confirma
        ↓
    Agent cancela rollback
        ↓
    CONFIRMADA

Se não houver confirmação:

    Agent executa rollback automaticamente.

IMPORTANTE
----------

O Django mantém `expira_em` para interface/auditoria.

Porém o mecanismo real de proteção NÃO pode depender:

- do navegador;
- de JavaScript;
- do processo web Django;
- de uma requisição futura.

O MoonShield-Agent será responsável pelo timer real de rollback.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from rede.dominio.erros import (
    AgentOperacaoRecusadaErro,
    AlteracaoEstadoInvalidoErro,
    AlteracaoExpiradaErro,
    AlteracaoNaoEncontradaErro,
    AlteracaoRedeErro,
    AplicacaoRedeErro,
    ConfiguracaoRedeInvalidaErro,
    RollbackRedeErro,
    SnapshotRedeErro,
)

from rede.dominio.tipos import (
    NivelEventoRede,
    StatusAlteracaoRede,
    TipoAlteracaoRede,
)

from rede.models import (
    AlteracaoRede,
    ConfiguracaoRoteamento,
    EventoRede,
    InterfaceRede,
    RegraNat,
    RotaEstatica,
    SnapshotRede,
)

from rede.services.agent_client import (
    requisitar_agent,
)

from rede.services.interfaces import (
    montar_payload_interface,
    montar_payload_interfaces,
    obter_interface_por_id,
)

from rede.services.nat import (
    montar_payload_nat,
    obter_regra_nat,
)

from rede.services.roteamento import (
    montar_payload_roteamento,
    obter_rota,
)


# =============================================================================
# CONSTANTES
# =============================================================================


STATUS_FINAIS = {
    AlteracaoRede.Status.CONFIRMADA,
    AlteracaoRede.Status.REVERTIDA,
    AlteracaoRede.Status.FALHOU,
    AlteracaoRede.Status.CANCELADA,
}


STATUS_QUE_PERMITEM_APLICACAO = {
    AlteracaoRede.Status.CRIADA,
}


STATUS_QUE_PERMITEM_CONFIRMACAO = {
    AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
}


STATUS_QUE_PERMITEM_ROLLBACK = {
    AlteracaoRede.Status.APLICANDO,
    AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
}


# =============================================================================
# SERIALIZAÇÃO
# =============================================================================


def serializar_alteracao(
    alteracao: AlteracaoRede,
) -> dict:
    """
    Serialização completa para API/frontend.
    """

    return {
        "id": str(
            alteracao.id
        ),

        "tipo": alteracao.tipo,

        "tipo_label": (
            alteracao.get_tipo_display()
        ),

        "status": alteracao.status,

        "status_label": (
            alteracao.get_status_display()
        ),

        "titulo": alteracao.titulo,

        "descricao": (
            alteracao.descricao
        ),

        "configuracao_solicitada": (
            alteracao.configuracao_solicitada
        ),

        "resultado_agent": (
            alteracao.resultado_agent
        ),

        "snapshot_anterior": (
            str(
                alteracao.snapshot_anterior_id
            )
            if alteracao.snapshot_anterior_id
            else None
        ),

        "snapshot_posterior": (
            str(
                alteracao.snapshot_posterior_id
            )
            if alteracao.snapshot_posterior_id
            else None
        ),

        "requer_confirmacao": (
            alteracao.requer_confirmacao
        ),

        "expira_em": _iso(
            alteracao.expira_em
        ),

        "iniciada_em": _iso(
            alteracao.iniciada_em
        ),

        "aplicada_em": _iso(
            alteracao.aplicada_em
        ),

        "confirmada_em": _iso(
            alteracao.confirmada_em
        ),

        "rollback_em": _iso(
            alteracao.rollback_em
        ),

        "finalizada_em": _iso(
            alteracao.finalizada_em
        ),

        "erro": alteracao.erro,

        "log": alteracao.log,

        "expirou": alteracao.expirou,

        "finalizada": alteracao.finalizada,

        "solicitado_por": (
            alteracao.solicitado_por.username
            if alteracao.solicitado_por
            else None
        ),

        "confirmado_por": (
            alteracao.confirmado_por.username
            if alteracao.confirmado_por
            else None
        ),

        "criado_em": _iso(
            alteracao.criado_em
        ),

        "atualizado_em": _iso(
            alteracao.atualizado_em
        ),
    }


def serializar_snapshot(
    snapshot: SnapshotRede,
) -> dict:
    return {
        "id": str(
            snapshot.id
        ),

        "origem": snapshot.origem,

        "backend": snapshot.backend,

        "automatico": (
            snapshot.automatico
        ),

        "valido": snapshot.valido,

        "observacao": (
            snapshot.observacao
        ),

        "dados": snapshot.dados,

        "criado_em": _iso(
            snapshot.criado_em
        ),
    }


# =============================================================================
# CONSULTAS
# =============================================================================


def obter_alteracao(
    alteracao_id: str | UUID,
    *,
    bloquear: bool = False,
) -> AlteracaoRede:
    """
    Obtém alteração pelo UUID.
    """

    queryset = (
        AlteracaoRede.objects
        .select_related(
            "snapshot_anterior",
            "snapshot_posterior",
            "solicitado_por",
            "confirmado_por",
        )
    )

    if bloquear:
        queryset = (
            queryset.select_for_update()
        )

    try:
        return queryset.get(
            pk=alteracao_id
        )

    except (
        AlteracaoRede.DoesNotExist,
        ValueError,
    ) as exc:
        raise AlteracaoNaoEncontradaErro(
            (
                f"Alteração de rede "
                f"'{alteracao_id}' não encontrada."
            )
        ) from exc


def listar_alteracoes(
    *,
    status: str | None = None,
    tipo: str | None = None,
    limite: int = 100,
) -> list[dict]:
    """
    Lista histórico recente.
    """

    try:
        limite = int(
            limite
        )
    except (
        TypeError,
        ValueError,
    ):
        limite = 100

    limite = max(
        1,
        min(
            limite,
            500,
        ),
    )

    queryset = (
        AlteracaoRede.objects
        .select_related(
            "solicitado_por",
            "confirmado_por",
            "snapshot_anterior",
            "snapshot_posterior",
        )
        .all()
    )

    if status:
        queryset = queryset.filter(
            status=status
        )

    if tipo:
        queryset = queryset.filter(
            tipo=tipo
        )

    queryset = queryset[
        :limite
    ]

    return [
        serializar_alteracao(
            alteracao
        )
        for alteracao in queryset
    ]


# =============================================================================
# EVENTOS
# =============================================================================


def registrar_evento(
    *,
    nivel: str,
    codigo: str,
    titulo: str,
    mensagem: str = "",
    dados: dict | None = None,
    interface: InterfaceRede | None = None,
    alteracao: AlteracaoRede | None = None,
    usuario=None,
) -> EventoRede:
    """
    Registra evento operacional.
    """

    return EventoRede.objects.create(
        nivel=nivel,
        codigo=codigo,
        titulo=titulo,
        mensagem=mensagem,
        dados=dados or {},
        interface=interface,
        alteracao=alteracao,
        usuario=usuario,
    )


# =============================================================================
# CRIAÇÃO GENÉRICA
# =============================================================================


@transaction.atomic
def criar_alteracao(
    *,
    tipo: str,
    configuracao_solicitada: dict,
    titulo: str = "",
    descricao: str = "",
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """
    Cria alteração no PostgreSQL.

    Não chama o Agent.
    """

    tipos_validos = {
        escolha[0]
        for escolha in AlteracaoRede.Tipo.choices
    }

    if tipo not in tipos_validos:
        raise ConfiguracaoRedeInvalidaErro(
            (
                f"Tipo de alteração de rede "
                f"inválido: '{tipo}'."
            )
        )

    if not isinstance(
        configuracao_solicitada,
        dict,
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "configuracao_solicitada "
                "deve ser um objeto."
            )
        )

    alteracao = AlteracaoRede.objects.create(
        tipo=tipo,
        status=(
            AlteracaoRede.Status.CRIADA
        ),
        titulo=str(
            titulo or ""
        ).strip(),
        descricao=str(
            descricao or ""
        ).strip(),
        configuracao_solicitada=(
            configuracao_solicitada
        ),
        requer_confirmacao=bool(
            requer_confirmacao
        ),
        solicitado_por=usuario,
    )

    alteracao.adicionar_log(
        "Alteração criada."
    )

    alteracao.save(
        update_fields=[
            "log",
            "atualizado_em",
        ]
    )

    registrar_evento(
        nivel=NivelEventoRede.INFO.value,
        codigo="network_change_created",
        titulo="Alteração de rede criada",
        mensagem=(
            alteracao.titulo
            or alteracao.get_tipo_display()
        ),
        alteracao=alteracao,
        usuario=usuario,
    )

    return alteracao


# =============================================================================
# CRIAÇÃO — INTERFACE
# =============================================================================


def criar_alteracao_interface(
    interface_id: int,
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """
    Cria alteração para uma interface já salva
    como estado desejado.
    """

    interface = obter_interface_por_id(
        interface_id
    )

    payload = montar_payload_interface(
        interface
    )

    return criar_alteracao(
        tipo=(
            TipoAlteracaoRede
            .INTERFACE
            .value
        ),

        titulo=(
            f"Configurar interface "
            f"{interface.nome}"
        ),

        descricao=(
            "Aplicação da configuração "
            "desejada da interface."
        ),

        configuracao_solicitada={
            "interface": payload,
        },

        usuario=usuario,

        requer_confirmacao=(
            requer_confirmacao
        ),
    )


# =============================================================================
# CRIAÇÃO — ROTEAMENTO
# =============================================================================


def criar_alteracao_roteamento(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    payload = (
        montar_payload_roteamento()
    )

    return criar_alteracao(
        tipo=(
            TipoAlteracaoRede
            .ROTEAMENTO
            .value
        ),

        titulo="Aplicar roteamento",

        descricao=(
            "Aplicação de IPv4 Forward "
            "e rotas estáticas."
        ),

        configuracao_solicitada=(
            payload
        ),

        usuario=usuario,

        requer_confirmacao=(
            requer_confirmacao
        ),
    )


# =============================================================================
# CRIAÇÃO — NAT
# =============================================================================


def criar_alteracao_nat(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    payload = (
        montar_payload_nat(
            somente_ativas=False
        )
    )

    return criar_alteracao(
        tipo=(
            TipoAlteracaoRede
            .NAT
            .value
        ),

        titulo="Aplicar configuração NAT",

        descricao=(
            "Aplicação das regras NAT "
            "administradas pelo MoonShield."
        ),

        configuracao_solicitada=(
            payload
        ),

        usuario=usuario,

        requer_confirmacao=(
            requer_confirmacao
        ),
    )


# =============================================================================
# CRIAÇÃO — CONFIGURAÇÃO COMPLETA
# =============================================================================


def criar_alteracao_geral(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """
    Cria alteração contendo todo o estado desejado da Rede.

    Será útil para:

        Aplicar Tudo
        onboarding
        recuperação
        instalação inicial
    """

    payload = {
        "interfaces": (
            montar_payload_interfaces()
            .get(
                "interfaces",
                [],
            )
        ),

        "roteamento": (
            montar_payload_roteamento()
        ),

        "nat": (
            montar_payload_nat(
                somente_ativas=False
            )
        ),
    }

    return criar_alteracao(
        tipo=(
            TipoAlteracaoRede
            .GERAL
            .value
        ),

        titulo=(
            "Aplicar configuração completa da rede"
        ),

        descricao=(
            "Aplicação completa do estado desejado "
            "de interfaces, roteamento e NAT."
        ),

        configuracao_solicitada=payload,

        usuario=usuario,

        requer_confirmacao=(
            requer_confirmacao
        ),
    )


# =============================================================================
# SNAPSHOT
# =============================================================================


def _criar_snapshot_de_resposta(
    dados: Any,
    *,
    usuario=None,
    observacao: str = "",
) -> SnapshotRede | None:
    """
    Persiste snapshot devolvido pelo Agent.

    Formatos aceitos:

    {
        "backend": "networkmanager",
        "dados": {...}
    }

    ou diretamente:

    {
        "interfaces": [...],
        "rotas": [...]
    }
    """

    if not dados:
        return None

    if not isinstance(
        dados,
        dict,
    ):
        raise SnapshotRedeErro(
            (
                "Snapshot devolvido pelo Agent "
                "possui formato inválido."
            )
        )

    backend = str(
        dados.get(
            "backend",
            "",
        )
        or ""
    )

    conteudo = dados.get(
        "dados"
    )

    if conteudo is None:
        conteudo = dados

    if not isinstance(
        conteudo,
        dict,
    ):
        raise SnapshotRedeErro(
            (
                "Dados internos do snapshot "
                "possuem formato inválido."
            )
        )

    return SnapshotRede.objects.create(
        origem="moonshield-agent",
        backend=backend,
        dados=conteudo,
        automatico=True,
        valido=True,
        observacao=observacao,
        criado_por=usuario,
    )


# =============================================================================
# PAYLOAD AGENT
# =============================================================================


def _montar_payload_agent(
    alteracao: AlteracaoRede,
) -> dict:
    """
    Contrato oficial para aplicação segura.

    O Agent DEVE:

    1. validar;
    2. criar snapshot;
    3. preparar rollback;
    4. armar o temporizador;
    5. aplicar;
    6. verificar;
    7. retornar somente depois do rollback estar armado.
    """

    config = ConfiguracaoRoteamento.atual()

    timeout = (
        config.tempo_confirmacao
    )

    if not alteracao.requer_confirmacao:
        timeout = 0

    return {
        "change_id": str(
            alteracao.id
        ),

        "type": alteracao.tipo,

        "safe_apply": True,

        "confirmation_required": (
            alteracao.requer_confirmacao
        ),

        "confirmation_timeout": (
            timeout
        ),

        "desired": (
            alteracao.configuracao_solicitada
        ),
    }


# =============================================================================
# APLICAÇÃO
# =============================================================================


def aplicar_alteracao(
    alteracao_id: str | UUID,
) -> AlteracaoRede:
    """
    Solicita aplicação segura ao Agent.

    Evitamos manter transaction PostgreSQL aberta
    durante chamada IPC.
    """

    # =========================================================================
    # 1. RESERVA ALTERAÇÃO
    # =========================================================================

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if (
            alteracao.status
            not in STATUS_QUE_PERMITEM_APLICACAO
        ):
            raise AlteracaoEstadoInvalidoErro(
                (
                    "Alteração não pode ser aplicada "
                    f"no estado '{alteracao.status}'."
                )
            )

        alteracao.status = (
            AlteracaoRede.Status.VALIDANDO
        )

        alteracao.iniciada_em = (
            timezone.now()
        )

        alteracao.erro = ""

        alteracao.adicionar_log(
            (
                "Iniciando validação e "
                "aplicação segura."
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "iniciada_em",
                "erro",
                "log",
                "atualizado_em",
            ]
        )

    # =========================================================================
    # 2. MONTA PAYLOAD
    # =========================================================================

    payload = _montar_payload_agent(
        alteracao
    )

    # =========================================================================
    # 3. MARCA APLICANDO
    # =========================================================================

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        alteracao.status = (
            AlteracaoRede.Status.APLICANDO
        )

        alteracao.adicionar_log(
            (
                "Solicitação enviada para "
                "MoonShield-Agent."
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "log",
                "atualizado_em",
            ]
        )

    # =========================================================================
    # 4. IPC
    # =========================================================================

    try:
        resultado = requisitar_agent(
            "network.change.apply",
            payload,
        )

    except Exception as exc:
        _registrar_falha_aplicacao(
            alteracao_id,
            exc,
        )

        if isinstance(
            exc,
            AlteracaoRedeErro,
        ):
            raise

        raise AplicacaoRedeErro(
            (
                "Falha ao solicitar aplicação "
                "da configuração de rede."
            ),
            detalhes={
                "erro": str(
                    exc
                )
            },
        ) from exc

    # =========================================================================
    # 5. PROCESSA RESPOSTA
    # =========================================================================

    try:
        snapshot_anterior = (
            _criar_snapshot_de_resposta(
                resultado.get(
                    "snapshot_before"
                ),
                usuario=(
                    alteracao.solicitado_por
                ),
                observacao=(
                    "Estado anterior à alteração "
                    f"{alteracao.id}"
                ),
            )
        )

        snapshot_posterior = (
            _criar_snapshot_de_resposta(
                resultado.get(
                    "snapshot_after"
                ),
                usuario=(
                    alteracao.solicitado_por
                ),
                observacao=(
                    "Estado após aplicação "
                    f"{alteracao.id}"
                ),
            )
        )

    except Exception as exc:
        # O Agent já pode ter aplicado a rede.
        #
        # Não solicitamos rollback automaticamente só
        # porque falhou a persistência do snapshot.
        #
        # O timer seguro do Agent continua responsável.
        _registrar_falha_aplicacao(
            alteracao_id,
            exc,
        )

        raise SnapshotRedeErro(
            (
                "A configuração foi processada pelo Agent, "
                "mas houve falha ao persistir os snapshots."
            ),
            detalhes={
                "erro": str(
                    exc
                )
            },
        ) from exc

    # =========================================================================
    # 6. ATUALIZA ALTERAÇÃO
    # =========================================================================

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        alteracao.resultado_agent = (
            resultado
        )

        alteracao.snapshot_anterior = (
            snapshot_anterior
        )

        alteracao.snapshot_posterior = (
            snapshot_posterior
        )

        alteracao.aplicada_em = (
            timezone.now()
        )

        expira_em = _resolver_expiracao(
            resultado,
            alteracao,
        )

        if alteracao.requer_confirmacao:
            alteracao.status = (
                AlteracaoRede
                .Status
                .AGUARDANDO_CONFIRMACAO
            )

            alteracao.expira_em = (
                expira_em
            )

            alteracao.adicionar_log(
                (
                    "Configuração aplicada. "
                    "Aguardando confirmação."
                )
            )

        else:
            alteracao.status = (
                AlteracaoRede.Status.CONFIRMADA
            )

            alteracao.confirmada_em = (
                timezone.now()
            )

            alteracao.finalizada_em = (
                timezone.now()
            )

            alteracao.expira_em = None

            alteracao.adicionar_log(
                (
                    "Configuração aplicada "
                    "sem confirmação pendente."
                )
            )

        alteracao.save(
            update_fields=[
                "resultado_agent",
                "snapshot_anterior",
                "snapshot_posterior",
                "aplicada_em",
                "status",
                "expira_em",
                "confirmada_em",
                "finalizada_em",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=(
            NivelEventoRede.SUCCESS.value
        ),

        codigo="network_change_applied",

        titulo=(
            "Configuração de rede aplicada"
        ),

        mensagem=(
            (
                "Aguardando confirmação."
                if alteracao.requer_confirmacao
                else "Aplicação concluída."
            )
        ),

        dados={
            "alteracao_id": str(
                alteracao.id
            ),

            "expira_em": _iso(
                alteracao.expira_em
            ),
        },

        alteracao=alteracao,

        usuario=(
            alteracao.solicitado_por
        ),
    )

    return alteracao


# =============================================================================
# CONFIRMAÇÃO
# =============================================================================


def confirmar_alteracao(
    alteracao_id: str | UUID,
    *,
    usuario=None,
) -> AlteracaoRede:
    """
    Confirma que o administrador manteve acesso.

    O Agent deverá cancelar o timer de rollback.
    """

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if (
            alteracao.status
            not in STATUS_QUE_PERMITEM_CONFIRMACAO
        ):
            raise AlteracaoEstadoInvalidoErro(
                (
                    "Alteração não está aguardando "
                    "confirmação."
                )
            )

        if alteracao.expirou:
            raise AlteracaoExpiradaErro(
                (
                    "O prazo de confirmação "
                    "da alteração expirou."
                )
            )

        payload = (
            _payload_operacao_agent(
                alteracao
            )
        )

    # Não mantemos lock durante IPC.
    try:
        resultado = requisitar_agent(
            "network.change.confirm",
            payload,
        )

    except Exception as exc:
        raise AlteracaoRedeErro(
            (
                "Não foi possível confirmar "
                "a alteração no Agent."
            ),
            detalhes={
                "erro": str(
                    exc
                )
            },
        ) from exc

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if (
            alteracao.status
            != AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        ):
            raise AlteracaoEstadoInvalidoErro(
                (
                    "Estado da alteração mudou "
                    "durante a confirmação."
                )
            )

        agora = timezone.now()

        alteracao.status = (
            AlteracaoRede.Status.CONFIRMADA
        )

        alteracao.confirmada_em = (
            agora
        )

        alteracao.finalizada_em = (
            agora
        )

        alteracao.confirmado_por = (
            usuario
        )

        alteracao.expira_em = None

        alteracao.resultado_agent = {
            **(
                alteracao.resultado_agent
                or {}
            ),

            "confirmation": resultado,
        }

        alteracao.adicionar_log(
            (
                "Alteração confirmada. "
                "Rollback automático cancelado."
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "confirmada_em",
                "finalizada_em",
                "confirmado_por",
                "expira_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=(
            NivelEventoRede.SUCCESS.value
        ),

        codigo="network_change_confirmed",

        titulo=(
            "Alteração de rede confirmada"
        ),

        mensagem=(
            alteracao.titulo
            or "Alteração confirmada"
        ),

        alteracao=alteracao,

        usuario=usuario,
    )

    return alteracao


# =============================================================================
# ROLLBACK
# =============================================================================


def executar_rollback(
    alteracao_id: str | UUID,
    *,
    usuario=None,
    motivo: str = "Rollback solicitado.",
) -> AlteracaoRede:
    """
    Solicita restauração do snapshot anterior.
    """

    # =========================================================================
    # PREPARA
    # =========================================================================

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if (
            alteracao.status
            not in STATUS_QUE_PERMITEM_ROLLBACK
        ):
            raise AlteracaoEstadoInvalidoErro(
                (
                    "Rollback não permitido "
                    f"no estado '{alteracao.status}'."
                )
            )

        alteracao.status = (
            AlteracaoRede.Status.ROLLBACK
        )

        alteracao.rollback_em = (
            timezone.now()
        )

        alteracao.adicionar_log(
            motivo
        )

        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "log",
                "atualizado_em",
            ]
        )

        payload = (
            _payload_operacao_agent(
                alteracao
            )
        )

        payload[
            "reason"
        ] = motivo

    # =========================================================================
    # AGENT
    # =========================================================================

    try:
        resultado = requisitar_agent(
            "network.change.rollback",
            payload,
        )

    except Exception as exc:
        with transaction.atomic():
            alteracao = obter_alteracao(
                alteracao_id,
                bloquear=True,
            )

            alteracao.status = (
                AlteracaoRede.Status.FALHOU
            )

            alteracao.erro = (
                f"Rollback falhou: {exc}"
            )

            alteracao.finalizada_em = (
                timezone.now()
            )

            alteracao.adicionar_log(
                alteracao.erro
            )

            alteracao.save(
                update_fields=[
                    "status",
                    "erro",
                    "finalizada_em",
                    "log",
                    "atualizado_em",
                ]
            )

        registrar_evento(
            nivel=(
                NivelEventoRede.ERROR.value
            ),

            codigo=(
                "network_rollback_failed"
            ),

            titulo="Rollback de rede falhou",

            mensagem=str(
                exc
            ),

            alteracao=alteracao,

            usuario=usuario,
        )

        raise RollbackRedeErro(
            (
                "MoonShield-Agent não conseguiu "
                "confirmar o rollback."
            ),
            detalhes={
                "erro": str(
                    exc
                )
            },
        ) from exc

    # =========================================================================
    # CONCLUÍDO
    # =========================================================================

    snapshot_posterior = None

    if resultado.get(
        "snapshot_after"
    ):
        snapshot_posterior = (
            _criar_snapshot_de_resposta(
                resultado.get(
                    "snapshot_after"
                ),
                usuario=usuario,
                observacao=(
                    "Estado após rollback "
                    f"{alteracao.id}"
                ),
            )
        )

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        agora = timezone.now()

        alteracao.status = (
            AlteracaoRede.Status.REVERTIDA
        )

        alteracao.finalizada_em = (
            agora
        )

        alteracao.expira_em = None

        if snapshot_posterior:
            alteracao.snapshot_posterior = (
                snapshot_posterior
            )

        alteracao.resultado_agent = {
            **(
                alteracao.resultado_agent
                or {}
            ),

            "rollback": resultado,
        }

        alteracao.adicionar_log(
            "Rollback concluído."
        )

        alteracao.save(
            update_fields=[
                "status",
                "finalizada_em",
                "expira_em",
                "snapshot_posterior",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=(
            NivelEventoRede.WARNING.value
        ),

        codigo="network_change_reverted",

        titulo=(
            "Alteração de rede revertida"
        ),

        mensagem=motivo,

        alteracao=alteracao,

        usuario=usuario,
    )

    return alteracao


# =============================================================================
# ALTERAÇÕES EXPIRADAS
# =============================================================================


def listar_alteracoes_expiradas():
    """
    Alterações que o Django considera vencidas.

    O Agent deve ser a autoridade real do timeout.
    """

    agora = timezone.now()

    return (
        AlteracaoRede.objects
        .filter(
            status=(
                AlteracaoRede
                .Status
                .AGUARDANDO_CONFIRMACAO
            ),

            expira_em__isnull=False,

            expira_em__lte=agora,
        )
        .order_by(
            "expira_em"
        )
    )


def reconciliar_alteracoes_expiradas() -> int:
    """
    Não dispara rollback cegamente.

    Pergunta ao Agent qual foi o resultado da operação.

    Isso é importante porque o Agent provavelmente já executou
    rollback sozinho quando o timer expirou.

    Contrato:

        network.change.status

    Resposta esperada:

        {
            "state": "reverted"
        }

    ou:

        {
            "state": "confirmed"
        }

    etc.
    """

    alteracoes = list(
        listar_alteracoes_expiradas()
    )

    processadas = 0

    for alteracao in alteracoes:
        try:
            resultado = requisitar_agent(
                "network.change.status",
                _payload_operacao_agent(
                    alteracao
                ),
            )

        except Exception:
            # Não alteramos estado sem saber
            # o que aconteceu no Linux.
            continue

        estado = str(
            resultado.get(
                "state",
                "",
            )
            or ""
        ).strip().lower()

        if estado in {
            "reverted",
            "rolled_back",
            "rollback",
        }:
            _marcar_revertida_por_agent(
                alteracao.id,
                resultado,
            )

            processadas += 1

        elif estado in {
            "confirmed",
            "committed",
        }:
            _marcar_confirmada_por_agent(
                alteracao.id,
                resultado,
            )

            processadas += 1

        elif estado in {
            "failed",
            "error",
        }:
            _marcar_falha_por_agent(
                alteracao.id,
                resultado,
            )

            processadas += 1

    return processadas


# =============================================================================
# CANCELAMENTO
# =============================================================================


@transaction.atomic
def cancelar_alteracao(
    alteracao_id: str | UUID,
    *,
    usuario=None,
) -> AlteracaoRede:
    """
    Só pode cancelar alteração que ainda não foi aplicada.
    """

    alteracao = obter_alteracao(
        alteracao_id,
        bloquear=True,
    )

    if (
        alteracao.status
        != AlteracaoRede.Status.CRIADA
    ):
        raise AlteracaoEstadoInvalidoErro(
            (
                "Somente alterações ainda não aplicadas "
                "podem ser canceladas."
            )
        )

    alteracao.status = (
        AlteracaoRede.Status.CANCELADA
    )

    alteracao.finalizada_em = (
        timezone.now()
    )

    alteracao.adicionar_log(
        "Alteração cancelada."
    )

    alteracao.save(
        update_fields=[
            "status",
            "finalizada_em",
            "log",
            "atualizado_em",
        ]
    )

    registrar_evento(
        nivel=(
            NivelEventoRede.WARNING.value
        ),

        codigo=(
            "network_change_cancelled"
        ),

        titulo=(
            "Alteração de rede cancelada"
        ),

        alteracao=alteracao,

        usuario=usuario,
    )

    return alteracao


# =============================================================================
# STATUS AGENT
# =============================================================================


def consultar_status_agent(
    alteracao_id: str | UUID,
) -> dict:
    """
    Consulta operação correspondente no Agent.
    """

    alteracao = obter_alteracao(
        alteracao_id
    )

    return requisitar_agent(
        "network.change.status",
        _payload_operacao_agent(
            alteracao
        ),
    )


# =============================================================================
# HELPERS — OPERAÇÃO AGENT
# =============================================================================


def _payload_operacao_agent(
    alteracao: AlteracaoRede,
) -> dict:
    """
    Extrai identificadores que o Agent retornou
    no momento da aplicação.
    """

    resultado = (
        alteracao.resultado_agent
        or {}
    )

    return {
        "change_id": str(
            alteracao.id
        ),

        "operation_id": (
            resultado.get(
                "operation_id"
            )
        ),

        "confirmation_token": (
            resultado.get(
                "confirmation_token"
            )
        ),
    }


# =============================================================================
# EXPIRAÇÃO
# =============================================================================


def _resolver_expiracao(
    resultado: dict,
    alteracao: AlteracaoRede,
) -> datetime | None:
    """
    Prefere expiração calculada pelo Agent.

    Se não vier, usa o timeout do PostgreSQL.
    """

    if not alteracao.requer_confirmacao:
        return None

    agent_expira = resultado.get(
        "expires_at"
    )

    if agent_expira:
        parsed = _datetime(
            agent_expira
        )

        if parsed:
            return parsed

    config = (
        ConfiguracaoRoteamento.atual()
    )

    return (
        timezone.now()
        + timedelta(
            seconds=(
                config.tempo_confirmacao
            )
        )
    )


# =============================================================================
# FALHA NA APLICAÇÃO
# =============================================================================


def _registrar_falha_aplicacao(
    alteracao_id,
    exc: Exception,
) -> None:
    """
    Persiste erro da aplicação.
    """

    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        agora = timezone.now()

        alteracao.status = (
            AlteracaoRede.Status.FALHOU
        )

        alteracao.erro = str(
            exc
        )

        alteracao.finalizada_em = (
            agora
        )

        alteracao.adicionar_log(
            (
                "Falha durante aplicação: "
                f"{exc}"
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "erro",
                "finalizada_em",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=(
            NivelEventoRede.ERROR.value
        ),

        codigo=(
            "network_change_failed"
        ),

        titulo=(
            "Falha na alteração de rede"
        ),

        mensagem=str(
            exc
        ),

        alteracao=alteracao,

        usuario=(
            alteracao.solicitado_por
        ),
    )


# =============================================================================
# RECONCILIAÇÃO — AGENT REVERTEU
# =============================================================================


def _marcar_revertida_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        alteracao.status = (
            AlteracaoRede.Status.REVERTIDA
        )

        alteracao.rollback_em = (
            alteracao.rollback_em
            or timezone.now()
        )

        alteracao.finalizada_em = (
            timezone.now()
        )

        alteracao.expira_em = None

        alteracao.resultado_agent = {
            **(
                alteracao.resultado_agent
                or {}
            ),
            "reconciliation": resultado,
        }

        alteracao.adicionar_log(
            (
                "Agent informou que o rollback "
                "automático foi executado."
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "finalizada_em",
                "expira_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=(
            NivelEventoRede.WARNING.value
        ),

        codigo=(
            "network_auto_rollback"
        ),

        titulo=(
            "Rollback automático executado"
        ),

        mensagem=(
            "A alteração não foi confirmada "
            "dentro do prazo."
        ),

        alteracao=alteracao,
    )


# =============================================================================
# RECONCILIAÇÃO — AGENT CONFIRMOU
# =============================================================================


def _marcar_confirmada_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        alteracao.status = (
            AlteracaoRede.Status.CONFIRMADA
        )

        alteracao.confirmada_em = (
            alteracao.confirmada_em
            or timezone.now()
        )

        alteracao.finalizada_em = (
            timezone.now()
        )

        alteracao.expira_em = None

        alteracao.resultado_agent = {
            **(
                alteracao.resultado_agent
                or {}
            ),
            "reconciliation": resultado,
        }

        alteracao.adicionar_log(
            (
                "Estado confirmado durante "
                "reconciliação com o Agent."
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "confirmada_em",
                "finalizada_em",
                "expira_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )


# =============================================================================
# RECONCILIAÇÃO — AGENT FALHOU
# =============================================================================


def _marcar_falha_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        mensagem = str(
            resultado.get(
                "error"
            )
            or resultado.get(
                "message"
            )
            or "Agent informou falha na operação."
        )

        alteracao.status = (
            AlteracaoRede.Status.FALHOU
        )

        alteracao.erro = (
            mensagem
        )

        alteracao.finalizada_em = (
            timezone.now()
        )

        alteracao.expira_em = None

        alteracao.resultado_agent = {
            **(
                alteracao.resultado_agent
                or {}
            ),
            "reconciliation": resultado,
        }

        alteracao.adicionar_log(
            (
                "Falha detectada durante "
                f"reconciliação: {mensagem}"
            )
        )

        alteracao.save(
            update_fields=[
                "status",
                "erro",
                "finalizada_em",
                "expira_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )


# =============================================================================
# HELPERS GERAIS
# =============================================================================


def _iso(
    valor: datetime | None,
) -> str | None:
    if valor is None:
        return None

    return valor.isoformat()


def _datetime(
    valor: Any,
) -> datetime | None:
    """
    Aceita datetime ou ISO 8601.
    """

    if isinstance(
        valor,
        datetime,
    ):
        resultado = valor

    elif isinstance(
        valor,
        str,
    ):
        resultado = parse_datetime(
            valor
        )

        if resultado is None:
            return None

    else:
        return None

    if timezone.is_naive(
        resultado
    ):
        resultado = timezone.make_aware(
            resultado
        )

    return resultado