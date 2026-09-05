# MoonShield — Guia Oficial de Desenvolvimento

## 1. Objetivo deste arquivo

Este arquivo define as regras obrigatórias para qualquer agente de código, incluindo Codex, que trabalhe no repositório MoonShield.

O projeto é conduzido pelo Pedro com apoio do ChatGPT como guia de arquitetura, revisão técnica, priorização e validação de decisões. O Codex deve atuar principalmente como executor técnico dentro do workspace: ler o código existente, implementar alterações, testar, revisar o diff e reportar claramente o que foi feito.

O Codex NÃO possui comunicação automática com o ChatGPT. Quando o usuário disser que uma decisão, regra ou arquitetura foi definida pelo ChatGPT, trate essa informação como parte da especificação fornecida pelo usuário.

---

# 2. Visão do produto

MoonShield é uma plataforma de segurança e gerenciamento de rede que deverá evoluir para um appliance Linux instalável, com futura imagem ISO própria baseada em Debian.

O produto combina:
- gerenciamento de interfaces;
- roteamento;
- NAT;
- firewall;
- DNS;
- IDS/IPS com Suricata;
- descoberta de dispositivos;
- monitoramento;
- incidentes;
- auditoria;
- diagnóstico;
- painel web;
- alterações de rede com Safe Apply.

Objetivo final: instalar MoonShield em máquina física ou virtual e usá-lo como gateway/firewall de rede.

---

# 3. Arquitetura principal

## 3.1 Django / Control Plane

Responsabilidades:
- interface web;
- APIs;
- autenticação;
- regras de negócio;
- estado desejado;
- topologia;
- histórico;
- auditoria;
- validação;
- orquestração;
- persistência em PostgreSQL;
- comparação desejado x real;
- reconciliação;
- integração entre módulos.

O Django NÃO deve executar diretamente:
- nmcli
- ip
- nft
- iptables
- ip6tables
- sysctl
- systemctl
- alterações privilegiadas de rede
- alterações diretas em /etc/NetworkManager
- alterações diretas em /etc/network
- alterações diretas de nftables

Essas responsabilidades pertencem ao MoonShield-Agent.

## 3.2 MoonShield-Agent / executor privilegiado

Responsabilidades:
- conversar com Linux;
- consultar NetworkManager;
- aplicar configurações;
- consultar estado real;
- executar operações privilegiadas;
- criar snapshots;
- executar rollback;
- manter timer real de rollback;
- aplicar nftables;
- aplicar NAT;
- consultar rotas;
- consultar interfaces;
- retornar resultados estruturados ao Django.

O Agent NÃO deve decidir:
- qual interface é WAN;
- qual interface é LAN;
- qual interface é MGMT;
- qual rede é HOME_NET;
- qual topologia o usuário escolheu;
- qual interface deve ser principal por regra de produto.

Essas decisões pertencem ao Django.

---

# 4. Fonte de verdade

Regra principal:

```text
PostgreSQL = estado desejado + histórico + auditoria
Linux      = estado real / observado
Agent      = executor e leitor privilegiado
Django     = cérebro / orquestrador
```

Nunca sobrescrever silenciosamente o estado desejado com o estado real.
Nunca assumir que o banco representa o estado atual do Linux.
Nunca assumir que o Linux está correto sem comparar com o desejado.

---

# 5. Network Control é a fonte oficial de topologia

O módulo `rede` deve comandar:
- WAN;
- LAN;
- MGMT;
- DMZ;
- redes internas;
- papéis das interfaces;
- gerenciamento administrativo;
- IPv4;
- gateway;
- rota padrão;
- métricas;
- MTU;
- roteamento;
- NAT;
- HOME_NET calculado;
- estado desejado;
- estado observado;
- divergência;
- reconciliação.

Firewall, DNS, Suricata e Dispositivos devem consumir dados do Network Control.

## Firewall
Recebe da Rede:
- WAN;
- LAN;
- MGMT;
- redes internas;
- HOME_NET;
- interfaces físicas correspondentes.

## DNS
Recebe:
- IP da LAN;
- redes internas;
- interfaces locais relevantes.

## Suricata
Recebe:
- HOME_NET;
- redes internas;
- interfaces monitoráveis.

## Dispositivos
Usa a classificação:
- WAN;
- LAN;
- MGMT;
- DMZ;
- CUSTOM.

---

# 6. Topologia suportada

Nunca hardcodar quantidade fixa de interfaces.
Nunca hardcodar nomes como enp0s3, enp0s8, eth0 ou ens18.

## 2 NICs
Obrigatórias:
- WAN
- LAN

MGMT dedicada é opcional.

Exemplo:
```text
NIC 1 = WAN
NIC 2 = LAN
MGMT dedicada = nenhuma
```

Gerenciamento pode ocorrer pela LAN.

## 3+ NICs
Exemplo:
```text
WAN  = enp0s3
LAN  = enp0s8
MGMT = enp0s9
```

MGMT continua opcional.

Papéis válidos:
- unassigned
- wan
- lan
- mgmt
- dmz
- custom

Regras:
- WAN != LAN;
- MGMT dedicada != WAN;
- MGMT dedicada != LAN;
- MGMT não é sinônimo de gerenciamento;
- LAN pode permitir acesso administrativo;
- unassigned = detectada, mas não gerenciada.

---

# 7. Estados das interfaces

Estados desejados:
- unmanaged
- synced
- pending_apply
- applying
- waiting_confirmation
- drifted
- missing
- error

## unmanaged
Interface detectada, mas ainda não administrada.

## synced
Desejado corresponde ao observado.

## pending_apply
Alteração desejada ainda não aplicada ao Linux.

## applying
Alteração em aplicação.

## waiting_confirmation
Aplicada e aguardando confirmação do Safe Apply.

## drifted
O Linux divergiu de uma configuração anteriormente aplicada.

## missing
Interface administrada não foi detectada.

## error
Falha de leitura, aplicação ou sincronização.

---

# 8. Estado desejado x observado

Preservar dois conceitos:

```text
desired
observed
```

Exemplo:
```json
{
  "desejado": {
    "papel": "lan",
    "ipv4_modo": "static",
    "ipv4_endereco": "10.10.0.1",
    "ipv4_prefixo": 24
  },
  "real": {
    "estado_link": "up",
    "ipv4": "10.10.0.1",
    "prefixo": 24
  }
}
```

O estado observado deve suportar múltiplos IPv4:
```json
{
  "enderecos_ipv4": [
    "10.53.52.49/24",
    "10.53.52.51/24"
  ]
}
```

---

# 9. Revisões de configuração

Conceitos:
```text
revisao_desejada
revisao_aplicada
```

Exemplo:
```text
desejada=5
aplicada=4
=> pending_apply
```

Depois de confirmação:
```text
desejada=5
aplicada=5
```

Se o Linux divergir com revisões iguais:
```text
desired != observed
=> drifted
```

---

# 10. Sincronização automática

Ao abrir páginas de Rede:
1. consultar estado;
2. consultar Agent quando necessário;
3. atualizar observado;
4. persistir observado;
5. comparar desejado x observado;
6. calcular status;
7. retornar ao frontend.

`Atualizar` = força nova leitura.
`Detectar interfaces` = força inventário.
`Reconciliar` = força comparação completa.

Reconciliação não deve aplicar automaticamente mudanças destrutivas.

---

# 11. Safe Apply

Fluxo obrigatório:
```text
estado desejado
↓
validação
↓
snapshot
↓
Agent aplica
↓
rollback armado
↓
waiting_confirmation
↓
usuário confirma
↓
rollback desarmado
↓
confirmed
```

Sem confirmação:
```text
waiting_confirmation
↓
rollback
↓
reverted
```

O timer real de rollback NÃO pode depender:
- do navegador;
- de JavaScript;
- do processo Django;
- de uma futura requisição HTTP.

O timer real pertence ao Agent.

---

# 12. Proteção administrativa

Nunca alterar de forma destrutiva uma interface que mantém acesso administrativo sem Safe Apply.
Nunca derrubar WAN/LAN ativa silenciosamente.
Sempre preservar rollback.

---

# 13. Firewall

Firewall usa nftables.

Regras:
- nunca usar `nft flush ruleset` como comportamento normal;
- nunca apagar regras externas ao namespace MoonShield;
- trabalhar somente nas tabelas/chains do MoonShield;
- preservar conexões estabelecidas;
- validar bloqueios globais perigosos;
- preservar acesso administrativo.

Firewall já possui fluxo validado:
```text
Django → Agent → nftables
```

Não reescrever sem necessidade.

---

# 14. NAT

NAT pertence ao módulo Rede.

Firewall:
- ALLOW
- DENY
- DROP
- REJECT

Rede:
- MASQUERADE
- NAT
- roteamento
- saída LAN → WAN

Caso comum:
```text
LAN 10.10.0.0/24
↓
WAN
↓
MASQUERADE
```

---

# 15. HOME_NET

O usuário não deve precisar digitar HOME_NET no fluxo normal.

Se LAN:
```text
10.10.0.1/24
```

Django calcula:
```text
10.10.0.0/24
```

Na UI usar preferencialmente:
```text
Rede interna
```

---

# 16. NetworkManager

NetworkManager é o backend oficial da V1.

MoonShield deve:
- detectar instalação;
- instalar no bootstrap se necessário;
- habilitar;
- iniciar;
- usar profiles persistentes;
- preservar rede após reboot.

Nunca assumir que NetworkManager já existe em Linux limpo.
Nunca migrar automaticamente uma interface ativa de forma destrutiva no bootstrap.

---

# 17. PostgreSQL

PostgreSQL é o banco de produção.

Persistir:
- interfaces;
- desejado;
- observado;
- papéis;
- roteamento;
- NAT;
- histórico;
- alterações;
- snapshots;
- auditoria;
- configurações.

SQLite é somente DEV quando selecionado explicitamente.

Nunca criar fallback automático entre SQLite e PostgreSQL.

---

# 18. DATABASE_URL

DEV:
```env
DATABASE_URL=sqlite:///banco_dados.sqlite3
```

PROD:
```env
DATABASE_URL=postgresql://moonshield:moonshield@127.0.0.1:5432/moonshield
```

Nunca modificar `.env` sem pedido explícito.
Nunca criar segredo novo hardcoded.

---

# 19. Migrations

Ao alterar models:
1. informar que migration é necessária;
2. gerar migration nova;
3. nunca apagar migrations antigas;
4. nunca editar migration já aplicada em produção;
5. reportar nome da migration criada.

---

# 20. Frontend

Não alterar visual sem necessidade quando a tarefa é lógica.

Preservar:
- IDs;
- data-*;
- Safe Apply;
- drawer;
- sidebar;
- toasts;
- responsividade.

Não quebrar:
- Aplicar Tudo;
- Histórico;
- Safe Apply;
- Rollback;
- navegação.

---

# 21. Estilo de código

Preferir:
- compacto;
- legível;
- explícito;
- modular;
- consistente.

Evitar verticalização excessiva.

Evitar:
```python
interface.ipv4_atual = (
    item.get(
        "ipv4"
    )
    or None
)
```

Preferir:
```python
interface.ipv4_atual = item.get("ipv4") or None
```

Mas não minificar de forma ilegível.

---

# 22. Fluxo obrigatório de desenvolvimento

Antes de editar:
1. ler AGENTS.md;
2. identificar arquivos relacionados;
3. procurar consumidores;
4. entender contratos;
5. verificar impacto;
6. preservar compatibilidade;
7. informar se o Agent precisa mudar.

Durante:
1. alterar somente arquivos permitidos;
2. não fazer refatorações fora do escopo;
3. não alterar arquitetura sem necessidade;
4. não alterar Agent se a tarefa disser Django apenas;
5. não alterar frontend se a tarefa disser backend apenas;
6. não mexer em configuração sem pedido.

Depois:
1. validar sintaxe;
2. rodar testes relevantes;
3. rodar Django check quando possível;
4. revisar git diff;
5. listar arquivos;
6. listar testes;
7. informar erros;
8. informar migration;
9. informar necessidade de mudança no Agent;
10. nunca esconder falhas.

---

# 23. Regra de lotes

Padrão:
```text
máximo 3 arquivos por lote
```

Se precisar de um quarto:
- pare;
- explique qual;
- explique por quê;
- aguarde autorização.

---

# 24. Git

Antes:
```bash
git status
```

Depois:
```bash
git diff
```

Nunca executar sem autorização explícita:
```bash
git reset --hard
git clean -fd
```

Nunca descartar mudanças locais silenciosamente.

---

# 25. Windows x Linux

No Windows pode validar:
- sintaxe;
- imports;
- Django;
- migrations;
- serializers;
- services;
- APIs;
- JS;
- testes unitários.

Não tentar validar no Windows:
- NetworkManager;
- nmcli;
- nft;
- systemctl;
- socket Unix;
- /run/moonshield/agent.sock;
- interfaces Linux reais;
- Suricata real.

Isso deve ser validado na VM Linux.

---

# 26. Ambiente Linux de laboratório

Exemplo atual:
```text
WAN  = enp0s3
LAN  = enp0s8
MGMT = nenhuma dedicada
```

Esses nomes são apenas do laboratório.
Nunca hardcodar.

Evitar alterações destrutivas na interface usada para administração.

---

# 27. Persistência após reboot

Antes de considerar Rede finalizado:
```text
reboot
↓
NetworkManager sobe
↓
WAN volta
↓
LAN volta
↓
rota volta
↓
NAT volta
↓
Firewall volta
↓
Agent volta
↓
Django reconcilia
↓
painel mostra estado correto
```

---

# 28. Appliance / ISO

Só iniciar ISO depois de validar:
- Network;
- Firewall;
- DNS;
- Suricata;
- integrações;
- reboot;
- bootstrap em Linux limpo.

Destino:
- Debian 13 amd64;
- systemd;
- PostgreSQL;
- NetworkManager;
- Agent;
- Django;
- Firewall;
- DNS;
- Suricata;
- console local.

---

# 29. Segurança

Nunca:
- expor tokens;
- versionar `.env`;
- hardcodar secrets;
- remover CSRF;
- remover autenticação;
- abrir privilégios desnecessários;
- executar comando privilegiado via Django;
- criar endpoint administrativo sem autenticação.

A auditoria completa de hardening será feita no fim do projeto. Durante o desenvolvimento atual, priorizar funcionalidade correta sem transformar cada tarefa em auditoria genérica.

---

# 30. Prioridade atual

Ordem oficial:
1. interfaces desired/observed;
2. reconciliação;
3. topologia;
4. overview;
5. roteamento;
6. NAT;
7. Safe Apply;
8. diagnóstico;
9. Network → Firewall;
10. Network → DNS;
11. Network → Suricata;
12. reboot/persistência;
13. appliance/ISO.

---

# 31. Lotes atuais

## Lote 1
- `MoonShield/aplicativos/rede/models.py`
- `MoonShield/aplicativos/rede/services/interfaces.py`
- `MoonShield/aplicativos/rede/dominio/tipos.py`

Objetivos:
- desired x observed;
- status;
- revisões;
- múltiplos IPv4;
- drift;
- compatibilidade.

## Lote 2
- `MoonShield/aplicativos/rede/dominio/validacoes.py`
- `MoonShield/aplicativos/rede/services/reconciliacao.py`
- `MoonShield/aplicativos/rede/services/inventario.py`

Objetivos:
- validações;
- reconciliação;
- atualização automática;
- inventário observado.

## Lote 3
- `MoonShield/aplicativos/rede/api/interfaces.py`
- `MoonShield/aplicativos/rede/api/status.py`
- `MoonShield/aplicativos/rede/api/urls.py`

## Lote 4
- `MoonShield/aplicativos/rede/services/topologia.py`
- `MoonShield/aplicativos/rede/api/topologia.py`
- `MoonShield/aplicativos/rede/dominio/constantes.py`

## Lote 5
- `MoonShield/static/js/rede/secoes/interfaces.js`
- `MoonShield/templates/rede/parciais/_interfaces.html`
- `MoonShield/static/js/rede/painel.js`

## Lote 6
- `MoonShield/static/js/rede/secoes/visao_geral.js`
- `MoonShield/templates/rede/parciais/_visao_geral.html`
- `MoonShield/aplicativos/rede/api/status.py`

## Lote 7
- `MoonShield/aplicativos/rede/services/roteamento.py`
- `MoonShield/aplicativos/rede/api/roteamento.py`
- `MoonShield/static/js/rede/secoes/roteamento_nat.js`

## Lote 8
- `MoonShield/aplicativos/rede/services/nat.py`
- `MoonShield/aplicativos/rede/api/nat.py`
- `MoonShield/templates/rede/parciais/_roteamento_nat.html`

## Lote 9
- `MoonShield/aplicativos/rede/services/alteracoes.py`
- `MoonShield/aplicativos/rede/api/alteracoes.py`
- `MoonShield/static/js/rede/componentes/safe_apply.js`

## Lote 10
- `MoonShield/aplicativos/rede/services/diagnostico.py`
- `MoonShield/aplicativos/rede/api/diagnostico.py`
- `MoonShield/static/js/rede/secoes/diagnostico.js`

---

# 32. Formato de resposta do Codex

Ao terminar cada tarefa, responder:

```text
Resumo
- ...

Arquivos alterados
- ...

Implementação
- ...

Compatibilidade
- ...

Migration
- necessária / não necessária

Testes executados
- comando
- resultado

Agent
- precisa / não precisa mudar

Pendências
- ...
```

Nunca responder apenas "feito".

---

# 33. Quando parar e pedir autorização

Parar antes de:
- alterar mais de 3 arquivos;
- quebrar contrato Django ↔ Agent;
- apagar campo/model;
- apagar migration;
- remover tabela;
- mudar Safe Apply estruturalmente;
- alterar WAN ativa;
- executar comando destrutivo;
- modificar `.env`;
- mudar arquitetura central;
- alterar Django e Agent no mesmo lote sem autorização.

---

# 34. Relação Codex + ChatGPT

Fluxo preferencial:

```text
Pedro
↓
ChatGPT ajuda a definir arquitetura, prioridade e critérios
↓
Pedro fornece tarefa ao Codex
↓
Codex lê workspace
↓
Codex implementa
↓
Codex testa
↓
Codex mostra diff
↓
Pedro valida em Linux quando necessário
↓
ChatGPT revisa resultado e orienta próximo passo
↓
próximo lote
```

O Codex deve respeitar decisões arquiteturais fornecidas pelo usuário, inclusive quando ele disser que foram definidas junto com o ChatGPT.

Se houver conflito entre sugestão automática do Codex e este documento, este documento prevalece.
Se houver conflito entre este documento e uma instrução explícita mais recente do usuário, a instrução explícita do usuário prevalece.

---

# 35. Regra final

Antes de qualquer alteração relevante:

> Leia este arquivo inteiro.

Depois:

> Entenda o fluxo atual antes de editar.

Durante:

> Altere somente o necessário.

Ao finalizar:

> Teste, revise o diff e reporte tudo.

O objetivo não é reescrever o MoonShield do zero.

O objetivo é finalizar o MoonShield de forma incremental, segura, coerente e testável.
