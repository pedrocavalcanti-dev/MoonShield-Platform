# MoonShield — AGENTS.md

## 1. Objetivo deste arquivo

Este é o arquivo OFICIAL de contexto, arquitetura, regras de desenvolvimento e checkpoint atual do projeto MoonShield.

Qualquer agente de código trabalhando neste repositório deve ler este arquivo antes de realizar alterações.

Não existe necessidade de consultar GEMINI.md.

Se existir um GEMINI.md antigo no workspace, ignore-o.

Uma instrução explícita e recente fornecida pelo usuário sempre prevalece sobre informações antigas deste arquivo quando houver conflito.

---

# 2. Papel dos agentes

Fluxo de trabalho:

Pedro
→ ChatGPT define/revisa arquitetura, prioridade e critérios
→ agente de código analisa o workspace
→ agente implementa
→ agente revisa
→ Pedro valida quando necessário
→ ChatGPT revisa
→ próximo lote

O agente de código é principalmente um executor técnico.

Antes de editar:

1. leia este AGENTS.md;
2. leia os arquivos relacionados;
3. procure produtores e consumidores;
4. entenda os contratos existentes;
5. verifique impacto;
6. preserve funcionalidades já validadas.

Não reescreva o MoonShield do zero.

Prefira alterações incrementais, pequenas, coerentes e auditáveis.

---

# 3. Produto atual

O foco é 100%:

MOONSHIELD APPLIANCE ISO

Não estamos mais desenvolvendo uma instalação Linux genérica.

Destino final:

- Debian 13 amd64;
- ISO própria;
- PostgreSQL;
- NetworkManager;
- nftables;
- Suricata;
- AdGuard Home;
- MoonShield Agent;
- Django;
- Gunicorn;
- Nginx;
- systemd;
- console local;
- interface web MoonShield.

Experiência final:

ISO MoonShield
↓
instala Debian + componentes internos
↓
primeiro boot
↓
serviços sobem automaticamente
↓
console local
↓
usuário acessa painel MoonShield
↓
login
↓
onboarding inicial
↓
configura WAN / LAN / MGMT
↓
usa o equipamento normalmente pelo painel MoonShield

A ISO deve conter os componentes necessários para a instalação base.

Internet será usada posteriormente para:

- updates;
- feeds;
- regras;
- listas;
- integrações externas.

---

# 4. Princípio do produto

MoonShield é uma appliance.

Portanto:

- AdGuard faz parte da appliance;
- Suricata faz parte da appliance;
- nftables faz parte da appliance;
- NetworkManager faz parte da appliance;
- MoonShield Agent faz parte da appliance;
- Django faz parte da appliance.

O usuário NÃO deve:

- instalar AdGuard manualmente;
- instalar Suricata manualmente;
- instalar nftables manualmente;
- conectar um AdGuard remoto para o funcionamento padrão;
- cadastrar host/token para o Firewall local;
- configurar serviços internos como providers;
- escolher entre DEMO/REAL/PROD para utilizar os serviços reais.

A operação normal acontece exclusivamente pela interface MoonShield.

---

# 5. Arquitetura principal

Fluxo:

Browser
↓
Nginx
↓
Django / Gunicorn
↓
MoonShield Agent
↓
Linux

Componentes Linux:

- NetworkManager;
- nftables;
- Suricata;
- AdGuard Home;
- systemd.

---

# 6. Django / Control Plane

Django é o cérebro/control plane.

Responsabilidades:

- interface web;
- APIs;
- autenticação;
- regras de negócio;
- desired state;
- topologia;
- validação lógica;
- histórico;
- auditoria;
- reconciliação;
- persistência;
- integração entre módulos;
- políticas;
- orquestração.

PostgreSQL é utilizado para:

- configurações persistentes;
- desired state;
- histórico;
- auditoria;
- entidades do produto.

Django NÃO deve executar diretamente:

- nmcli;
- ip;
- nft;
- iptables;
- ip6tables;
- sysctl;
- systemctl;
- alterações privilegiadas;
- alterações diretas em NetworkManager;
- alterações diretas em nftables;
- mudanças críticas do Linux.

Operações privilegiadas pertencem ao MoonShield Agent.

---

# 7. MoonShield Agent

O Agent é o executor privilegiado e leitor do estado real.

Responsabilidades:

- NetworkManager;
- nftables;
- rotas;
- NAT;
- sysctl;
- systemd;
- leitura do Linux;
- aplicação de configurações;
- snapshots;
- rollback;
- Safe Apply;
- Suricata;
- operações privilegiadas.

O Agent NÃO decide sozinho:

- WAN;
- LAN;
- MGMT;
- DMZ;
- CUSTOM;
- HOME_NET;
- rede interna;
- política de produto;
- topologia desejada.

Essas decisões pertencem ao Django e ao módulo `rede`.

---

# 8. Fonte de verdade

Regra principal:

PostgreSQL = estado desejado / configuração persistente

Linux = estado observado

Django = decisão e orquestração

Agent = execução privilegiada

Nunca assumir:

banco == Linux

Nunca substituir estado desejado silenciosamente pelo estado observado.

---

# 9. Rede é a fonte oficial da topologia

O app:

MoonShield/aplicativos/rede

é a fonte oficial de:

- interfaces;
- WAN;
- LAN;
- MGMT;
- DMZ;
- CUSTOM;
- UNASSIGNED;
- IPv4;
- gateway;
- rota default;
- métricas;
- MTU;
- roteamento;
- NAT;
- redes internas;
- desired;
- observed;
- drift;
- reconciliação;
- HOME_NET derivado.

Consumidores devem utilizar `rede`:

- Firewall;
- Suricata;
- AdGuard;
- Devices;
- Dashboard;
- Diagnóstico;
- Incidentes;
- Configurações.

Nunca criar segunda fonte de verdade de WAN/LAN/HOME_NET.

---

# 10. Topologia

Papéis válidos:

- unassigned;
- wan;
- lan;
- mgmt;
- dmz;
- custom.

Nunca hardcodar:

- enp0s3;
- enp0s8;
- ens18;
- eno1;
- eth0;
- quantidade fixa de interfaces.

Esses nomes podem existir em laboratório, mas não pertencem à regra de produto.

2 interfaces:

- WAN obrigatória;
- LAN obrigatória;
- gerenciamento pode ocorrer pela LAN.

3 ou mais interfaces:

- WAN;
- LAN;
- MGMT opcional;
- DMZ/CUSTOM/etc.

Nunca assumir:

terceira interface = MGMT

WAN != LAN.

---

# 11. Desired / Observed / Drift

Preservar:

desired
observed

Revisões:

revisao_desejada
revisao_aplicada

Estados esperados:

- unmanaged;
- synced;
- pending_apply;
- applying;
- waiting_confirmation;
- drifted;
- missing;
- error.

Se:

revisao_desejada > revisao_aplicada

→ pending_apply

Se:

revisao_desejada == revisao_aplicada
e desired != observed

→ drifted

---

# 12. Safe Apply

Safe Apply já está implementado e validado.

Fluxo oficial:

desired
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
confirmação
↓
rollback desarmado
↓
confirmed

Sem confirmação:

timeout
↓
rollback
↓
reverted

O timer real pertence ao Agent.

Nunca depender de:

- browser;
- JavaScript;
- Django;
- nova requisição HTTP.

Não alterar estruturalmente Safe Apply sem autorização explícita.

---

# 13. NetworkManager

NetworkManager é o backend oficial de rede.

Utilizar:

- profiles persistentes;
- detecção dinâmica;
- Agent;
- desired/observed;
- Safe Apply;
- persistência após reboot.

Não alterar uma interface administrativa de maneira destrutiva.

Não hardcodar IP ou gateway da WAN.

---

# 14. Roteamento

Roteamento pertence ao módulo Rede.

Já está integrado ao Agent e NetworkManager.

Deve preservar:

- rota administrativa;
- rotas externas;
- ownership;
- desired;
- observed;
- Safe Apply.

Rota estática MoonShield é diferente de rota externa/manual.

Default route pertence à WAN.

Não criar segunda fonte de verdade para default route.

---

# 15. NAT

NAT já está integrado e validado.

Namespace MoonShield:

table ip moonshield_nat

Responsabilidades:

- MASQUERADE;
- LAN → WAN;
- IPv4 forwarding;
- integração com topologia.

Não usar NAT para manipular configuração WAN.

Nunca destruir tabelas externas.

---

# 16. Firewall

Backend:

nftables

Contrato:

Django
↓
Agent
↓
nftables

Namespace MoonShield deve ser isolado.

Nunca usar:

nft flush ruleset

como comportamento normal.

Preservar:

- regras externas;
- conexões estabelecidas;
- acesso administrativo;
- namespaces não pertencentes ao MoonShield.

Firewall é componente local da appliance.

Não tratar Firewall como provider remoto.

---

# 17. Suricata

Versão validada no appliance:

Suricata 7.0.10

Modo atual:

IDS passivo

Fluxo:

rede
↓
Django
↓
Agent
↓
Suricata

Topologia vem do módulo `rede`.

HOME_NET não deve ser preenchido manualmente no fluxo normal.

Agent recebe a configuração desejada.

Agent não decide HOME_NET.

Ações IPC existentes incluem operações de:

- status;
- diagnostics;
- config validate;
- config apply;
- service status;
- service start;
- service stop;
- service restart.

Status desejado/observado e drift já foram validados.

Reboot/recovery já foi validado.

Teste com cliente LAN real ficou adiado para ambiente onde exista cliente físico/virtual apropriado.

Não reinstalar Suricata.

Não criar segundo fluxo de instalação.

Não executar Suricata diretamente pelo Django.

---

# 18. AdGuard Home

Versão atual da appliance:

AdGuard Home v0.107.79

Instalação:

/opt/AdGuardHome

Serviço:

AdGuardHome.service

DNS:

TCP/UDP 53

AdGuard é um componente local.

O usuário NÃO acessa normalmente o painel nativo do AdGuard.

O usuário utiliza o módulo DNS do MoonShield.

O módulo DNS MoonShield já possui:

- dashboard;
- queries;
- bloqueios;
- whitelist;
- filtros;
- regras;
- clientes;
- métricas;
- feed DNS.

Já foram validados pela UI:

- criação de BLOCK;
- criação de ALLOW;
- remoção de regra;
- listagem;
- métricas;
- clientes;
- feed;
- estado da API.

Não transformar AdGuard novamente em integração remota.

Não pedir ao usuário:

- URL do AdGuard;
- usuário;
- senha;
- HTTPS;
- endereço remoto.

Configurações deve apenas consumir estado do serviço.

---

# 19. IPC Django ↔ Agent

Socket:

/run/moonshield/agent.sock

Permissões esperadas:

root:moonshield
0660

Protocolos/actions existentes devem ser reutilizados.

Não criar action paralela quando já existir ação equivalente.

Não aumentar timeouts globais do Agent apenas para contornar operações específicas.

---

# 20. Serviços principais

Appliance validada anteriormente com:

- Debian 13;
- NetworkManager;
- PostgreSQL 17;
- Django;
- Gunicorn;
- Nginx;
- moonshield-web;
- MoonShield Agent;
- nftables;
- Suricata 7.0.10;
- AdGuard Home v0.107.79.

Componentes devem subir automaticamente após reboot.

---

# 21. Gunicorn / Django

Servidor Django:

Gunicorn

Não trocar para Uvicorn sem decisão arquitetural explícita.

Comando Django correto:

python gerenciar.py

NÃO usar:

python manage.py

---

# 22. PostgreSQL

Banco de produção:

PostgreSQL

Não criar fallback automático para SQLite.

Não modificar `.env` sem autorização.

Não hardcodar credenciais.

---

# 23. Frontend

Preservar quando não houver mudança explícita:

- sidebar;
- topbar;
- drawer;
- toasts;
- responsividade;
- identidade visual MoonShield.

Não fazer redesign geral junto com mudança lógica.

Pode remover elementos legados quando a tarefa pedir explicitamente.

---

# 24. Configurações — arquitetura atual desejada

Esta é a PRÓXIMA FASE ATIVA.

A tela Configurações deve ser adaptada para uma appliance instalada.

Não deve mais parecer um configurador de providers.

Objetivo:

CONFIGURAÇÕES DA MOONSHIELD APPLIANCE

Abas desejadas:

- Sistema;
- Rede;
- Scanner;
- Serviços;
- Segurança;
- Diagnóstico.

---

# 25. Configurações — remover legado

Remover da tela Configurações:

- Modo Simulação;
- Modo Real;
- PROD;
- DEMO;
- MOCK;
- banner "Modo Real";
- seletor de modo;
- overlays de simulação;
- provider DNS;
- provider IDS;
- provider Firewall;
- STATE.providers quando usado somente por legado;
- PROV_STATUS quando usado somente por legado;
- AdGuard remoto;
- URL do AdGuard;
- usuário do AdGuard;
- senha do AdGuard;
- toggle HTTPS do AdGuard;
- botão Testar Conexão do AdGuard;
- host Firewall;
- token Firewall;
- porta configurável do Agent;
- target remoto;
- switches genéricos de provider;
- instalação de AdGuard;
- instalação de Suricata;
- instalação de Firewall;
- mensagens de "configure integração";
- badges REMOTO.

MoonShield Appliance utiliza runtime real.

Não substituir por "Modo Appliance".

Simplesmente remover o conceito de modo operacional.

---

# 26. Configurações — Sistema

A aba Sistema pode mostrar:

- Hostname;
- Sistema operacional;
- IP;
- Timezone;
- Uptime;
- Python;
- Django;
- RAM;
- CPU quando disponível;
- Disco quando disponível;
- versão MoonShield quando disponível.

Identidade editável:

- Nome amigável;
- Ambiente administrativo;
- Local/Tag;
- Descrição.

O campo Ambiente pode ser:

LAB
Produção

Mas isso é somente metadata.

Não pode alterar comportamento dos serviços.

---

# 27. Configurações — Rede

Não duplicar o módulo Rede.

Configurações deve mostrar somente resumo.

Exemplo:

WAN
interface / estado / endereço

LAN
interface / estado / rede

MGMT
estado

Gateway
estado

Topologia
válida / atenção

Botão:

Gerenciar Rede

Esse botão abre o módulo oficial `rede`.

Não editar:

- CIDR;
- gateway;
- WAN;
- LAN;
- rotas;
- NAT;
- interface principal;

pela página Configurações.

Não selecionar automaticamente primeira interface como WAN.

---

# 28. Configurações — Scanner

Scanner continua configurável.

Preferências legítimas:

- intervalo;
- ping timeout;
- máximo de hosts;
- método;
- hostname;
- MAC;
- OUI/fabricante.

Scanner deve consumir a topologia oficial quando necessário.

Não criar sua própria verdade de rede.

---

# 29. Configurações — Serviços

A aba Serviços representa componentes locais da appliance.

Não representa providers.

## AdGuard

Mostrar, quando disponível:

- status;
- DNS Resolver;
- API;
- proteção;
- filtros;
- versão.

Ação:

Abrir DNS

Abrir o módulo DNS MoonShield.

Nunca abrir diretamente porta 3000 para usuário normal.

## Suricata

Mostrar:

- status;
- versão;
- Motor IDS;
- EVE;
- interface(s);
- HOME_NET;
- drift.

Ação:

Abrir IDS

## Firewall

Mostrar:

- status;
- engine nftables;
- Agent;
- drift;
- política quando disponível.

Ação:

Abrir Firewall

Os cards são informativos.

Não desligar serviços usando switches genéricos.

---

# 30. Configurações — Segurança

Pode persistir preferências do painel como:

- expiração de sessão;
- tentativas máximas;
- HTTPS quando aplicável;
- access log;
- IP ban;
- nível de log.

Não confundir isso com política do Firewall.

Não executar nftables nessa aba.

---

# 31. Configurações — Retenção

Manter, quando já existente:

- dispositivos;
- logs;
- DNS;
- incidentes.

Não alterar schema sem necessidade.

---

# 32. Configurações — Diagnóstico

Mostrar status consolidado:

- Rede;
- Agent;
- DNS / AdGuard;
- IDS / Suricata;
- Firewall;
- Web.

Diagnóstico é read-only por padrão.

Não instalar serviço.

Não reiniciar automaticamente ao abrir.

Não executar reparo destrutivo.

---

# 33. Estado global do frontend

Objetivo conceitual:

STATE = {
    node: {...},
    scanner: {...},
    retencao: {...},
    seguranca: {...},

    rede: {
        resumo operacional
    },

    servicos: {
        adguard: {...},
        suricata: {...},
        firewall: {...}
    }
}

`STATE.servicos` deve ser a fonte de verdade operacional.

Remover compatibilidade antiga de providers quando não houver mais consumidores reais.

Antes de remover estrutura compartilhada, procurar consumidores.

---

# 34. Backend Configurações

Ao alterar Configurações, analisar:

- models;
- views;
- APIs;
- urls;
- services;
- persistência;
- frontend relacionado.

Endpoints atuais devem ser auditados, incluindo quando existentes:

- /configuracoes/api/config/
- /configuracoes/api/servicos/
- /configuracoes/api/salvar/
- endpoints antigos de providers.

Não apagar endpoint compartilhado sem verificar consumidores.

Estado operacional não deve ser salvo como preferência de formulário.

Salvar alterações deve persistir apenas:

- identidade;
- scanner;
- retenção;
- segurança;
- preferências legítimas.

Não salvar como configuração editável:

- estado Suricata;
- estado AdGuard;
- estado Firewall;
- estado Rede observado.

---

# 35. Rotas frontend

Não hardcodar URLs.

Usar:

{% url ... %}

quando possível.

Se JavaScript precisar de rota:

- expor via data-* no template;
- reutilizar rota existente.

Não hardcodar IP da máquina.

Não hardcodar IP de laboratório.

---

# 36. Não alterar módulos funcionais durante Configurações

Na fase atual, NÃO refatorar internamente:

- Rede;
- Safe Apply;
- NAT;
- Firewall Agent;
- Suricata Agent;
- DNS/Regras AdGuard.

Configurações deve consumir esses módulos.

Se existir bug real neles, reportar separadamente.

---

# 37. Segurança

Nunca:

- expor tokens;
- versionar secrets;
- remover CSRF;
- remover autenticação;
- criar endpoint administrativo aberto;
- dar privilégio desnecessário;
- executar comando privilegiado diretamente no Django.

---

# 38. Windows x Linux

Windows pode ser utilizado para:

- leitura;
- edição;
- análise estática;
- sintaxe;
- imports;
- JS;
- Django;
- testes quando explicitamente autorizados.

Linux é responsável pela validação real de:

- NetworkManager;
- nmcli;
- nftables;
- systemd;
- socket Unix;
- Agent;
- rotas;
- interfaces;
- Suricata;
- AdGuard;
- reboot.

Não afirmar que teste Windows prova comportamento Linux.

---

# 39. Terminal — regra atual

O agente pode utilizar terminal/PowerShell SOMENTE PARA LEITURA, navegação e revisão estática do workspace.

Comandos read-only permitidos incluem:

- Get-ChildItem;
- Get-Content;
- Select-String;
- Test-Path;
- rg;
- grep;
- git status;
- git diff;
- git diff --check;
- git grep;
- git log;
- git show;
- git ls-files;
- git rev-parse.

Esses comandos não devem alterar arquivos ou estado do sistema.

O agente pode usar ferramentas nativas do editor quando disponíveis e deve preferi-las quando conveniente.

---

# 40. Terminal — proibido sem autorização

Sem autorização explícita, o agente NÃO pode:

- git add;
- git commit;
- git push;
- git pull;
- git reset;
- git restore;
- git checkout;
- git clean;
- alterar arquivos via shell;
- remover arquivos via shell;
- mover arquivos via shell;
- executar scripts modificadores;
- rodar migrations;
- rodar makemigrations;
- executar comandos Linux reais;
- alterar NetworkManager;
- alterar nftables;
- reiniciar serviços;
- instalar pacotes;
- modificar banco;
- modificar .env.

Testes e comandos Python só devem ser executados quando a tarefa/autorização atual permitir.

---

# 41. Git

Nunca usar:

git add .

como padrão.

Sempre adicionar arquivos específicos quando o usuário autorizar commit.

Nunca descartar mudanças locais silenciosamente.

Antes de recomendar commit:

- revisar arquivos alterados;
- revisar diff;
- confirmar que não há runtime logs;
- confirmar que não há secrets.

Arquivo conhecido que pode ficar sujo em runtime:

MoonShield/logs/moonshield.log

Não adicionar, restaurar ou commitar automaticamente.

---

# 42. Regra de lotes

Padrão de implementação:

máximo de 3 arquivos alterados por lote.

Para uma tarefa grande explicitamente autorizada, o agente pode continuar automaticamente:

analisar
↓
editar até 3 arquivos
↓
revisar
↓
próximo lote

Não precisa solicitar nova autorização entre cada lote quando o usuário já autorizou a tarefa completa.

Pare apenas se:

- surgir decisão arquitetural ambígua;
- precisar alterar arquitetura central;
- precisar quebrar contrato Django ↔ Agent;
- precisar alterar Django e Agent de forma estrutural conjunta;
- precisar apagar model/campo/tabela;
- precisar apagar migration;
- precisar mudar Safe Apply;
- precisar modificar .env;
- precisar alterar rede real;
- precisar executar operação destrutiva.

---

# 43. Migrations

Se model mudar:

- informar que migration é necessária;
- criar migration somente se autorizado;
- nunca apagar migration antiga;
- nunca editar migration já aplicada.

Se model não mudar:

Migration: não necessária.

Não executar migrate sem autorização.

---

# 44. Código

Preferir código:

- legível;
- compacto;
- explícito;
- modular;
- consistente com o projeto existente.

Não minificar.

Não verticalizar excessivamente código simples.

Não criar abstração sem necessidade.

---

# 45. Estado validado do projeto

Estado atual:

A1 Runtime / IPC / systemd
✅ CONCLUÍDO

A2 Contrato Django ↔ Agent
✅ CONCLUÍDO

A3 Observed preservation
✅ CONCLUÍDO

A4 NetworkManager real
✅ CONCLUÍDO

A5 Routing real
✅ CONCLUÍDO

A6 NAT + IPv4 Forward
✅ CONCLUÍDO

A7 Safe Apply / rollback / recovery
✅ CONCLUÍDO

A8 Drift / Reconciliation
✅ CONCLUÍDO

A9 Firewall / nftables
✅ CONCLUÍDO

A10 Suricata IDS
✅ CONCLUÍDO

A11 AdGuard / DNS
✅ CONCLUÍDO

A12 Configurações Appliance
🟠 FASE ATUAL

A13 integração final de consumidores
⏳ POSTERIOR

A14 boot / appliance / acabamento
⏳ POSTERIOR

ISO reproduzível
⏳ POSTERIOR

---

# 46. Validações recentes importantes

## Rede

Já validado:

- interfaces;
- desired/observed;
- routing;
- NAT;
- ip_forward;
- Safe Apply;
- confirmação;
- rollback;
- recovery;
- drift;
- reboot.

## Firewall

Integração nftables local concluída.

Namespaces externos devem permanecer preservados.

## Suricata

Já validado:

- serviço;
- configuração;
- status;
- validate;
- apply;
- restart;
- diagnóstico;
- Django → Agent;
- desired;
- observed;
- drift;
- reboot/recovery.

Teste de alerta com cliente LAN real pode ser realizado posteriormente quando houver cliente apropriado.

## AdGuard

Já validado:

- serviço active/enabled;
- v0.107.79;
- DNS TCP/UDP 53;
- resolução localhost;
- resolução LAN;
- Dashboard MoonShield;
- queries;
- clientes;
- métricas;
- feed;
- regras BLOCK;
- regras ALLOW;
- remoção;
- filtros.

---

# 47. Objetivo da fase A12

Refatorar Configurações para refletir a arquitetura Appliance.

Resultado esperado:

Configurações
├── Sistema
├── Rede
├── Scanner
├── Serviços
│   ├── AdGuard
│   ├── Suricata
│   └── Firewall
├── Segurança
└── Diagnóstico

Eliminar:

- demo/prod;
- modo simulação/real;
- providers;
- integração remota do AdGuard;
- credenciais do AdGuard;
- host/token Firewall;
- instalação de componentes;
- configuração duplicada da Rede.

Configurações deve funcionar como painel administrativo da appliance já instalada.

---

# 48. Critérios visuais A12

Ao abrir Configurações:

- não existe banner "Modo Real";
- não existe Simulação;
- não existe DEMO;
- não existe PROD;
- não existe MOCK;
- não existe REMOTO no AdGuard;
- não existem credenciais do AdGuard;
- não existem host/token do Firewall;
- não existe instalar Suricata;
- não existem switches provider;
- serviços aparecem locais e operacionais;
- Rede aparece como resumo;
- existe Gerenciar Rede;
- existe Abrir DNS;
- existe Abrir IDS;
- existe Abrir Firewall;
- Scanner continua editável;
- identidade continua editável;
- retenção continua editável;
- segurança continua editável.

---

# 49. Critérios técnicos A12

A página Configurações não pode:

- manipular NetworkManager;
- aplicar nftables;
- instalar packages;
- instalar serviços;
- executar systemctl diretamente no Django;
- escolher WAN/LAN no frontend;
- criar HOME_NET;
- criar segunda fonte de topologia;
- depender de mock;
- depender de provider remoto.

Estados operacionais devem vir dos módulos reais.

---

# 50. Próximas etapas após A12

Depois que Configurações estiver pronta e validada:

1. integração final de consumidores;
2. revisar Dashboard real;
3. Devices;
4. Incidentes/Eventos;
5. diagnóstico agregado;
6. onboarding inicial;
7. console local;
8. hardening;
9. HTTPS;
10. instalação reproduzível;
11. geração ISO;
12. instalação em VM limpa;
13. validação de reprodutibilidade.

Não pular diretamente para ISO antes de finalizar a experiência do appliance.

---

# 51. Regra de arquitetura final

Não inventar arquitetura paralela.

Não duplicar responsabilidade.

Não substituir contratos já validados.

Reutilizar:

rede
Agent
Firewall
Suricata
DNS/AdGuard

como já existem.

---

# 52. Formato de relatório do agente

Ao terminar uma implementação:

## RESUMO

- alterações realizadas.

## ARQUIVOS ALTERADOS

- lista exata.

## IMPLEMENTAÇÃO

- principais decisões.

## BACKEND

- APIs/services alterados.

## FRONTEND

- templates/JS/CSS alterados.

## MODEL

- SIM/NÃO.

## MIGRATION

- necessária/não necessária.

## AGENT

- alterado/não alterado.

## REDE REAL

- alterada/não alterada.

## TESTES

- executados ou não executados;
- motivo quando não autorizados.

## LEGADO REMOVIDO

- itens removidos.

## RISCOS / PENDÊNCIAS

- qualquer ponto restante.

## VALIDAÇÃO RECOMENDADA

- passos objetivos para Pedro validar.

Não responder apenas:

"feito".

---

# 53. Princípios finais

Prioridades:

1. não perder conectividade;
2. não destruir configuração externa;
3. ownership correto;
4. rollback confiável;
5. estado observado real;
6. idempotência;
7. persistência;
8. interface coerente;
9. facilidade de uso.

MoonShield deve se comportar como uma appliance de produção.

Toda mudança deve ser:

- determinística;
- auditável;
- segura;
- reversível quando aplicável;
- integrada à arquitetura existente.

Antes:
entenda o código.

Durante:
altere somente o necessário.

Depois:
revise o impacto.

Objetivo final:

MOONSHIELD APPLIANCE ISO
pronta para instalação reproduzível e operação integral pelo painel web.