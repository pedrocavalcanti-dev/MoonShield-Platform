```

███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗

████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗

██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║███████╗███████║██║█████╗  ██║     ██║  ██║

██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║

██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║███████║██║  ██║██║███████╗███████╗██████╔╝

╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝

```



<div align="center">



\### 🛡️ Plataforma Integrada de SOC/NOC — Projeto Educacional



\*\*Visibilidade total. Resposta rápida. Controle absoluto.\*\*



`v3.0` · Projeto Senac 2026 · Técnico em Redes de Computadores \& Segurança



!\[Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat\&logo=python\&logoColor=white)

!\[Django](https://img.shields.io/badge/Django-5.x-092E20?style=flat\&logo=django\&logoColor=white)

!\[Suricata](https://img.shields.io/badge/IDS-Suricata-E9420E?style=flat\&logo=suricata\&logoColor=white)

!\[License](https://img.shields.io/badge/Licença-MIT-blue?style=flat)

!\[Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow?style=flat)



</div>



\---



\## 📖 Sobre o Projeto



O \*\*MoonShield\*\* é uma plataforma educacional centralizada para operações de segurança (\*\*SOC\*\*) e monitoramento de rede (\*\*NOC\*\*). Desenvolvido em \*\*Django\*\*, consolida logs, métricas e alertas de diversas fontes — \*\*Suricata IDS\*\*, \*\*Firewall\*\* (iptables/nftables), \*\*DNS\*\* (AdGuard Home) — em uma única interface interativa e de alta performance.



Projetado para cursos técnicos, laboratórios de segurança e projetos integradores que precisam simular a rotina de um SOC/NOC com visibilidade total sobre a infraestrutura e agilidade na resposta a incidentes.



> Projeto desenvolvido por \*\*Pedro Cavalcanti\*\* no Técnico em Redes de Computadores · Senac São Paulo · 2026.



\### 🔗 Arquitetura unificada (v3.0)



A partir da v3.0, o \*\*painel web\*\* e o \*\*agente sensor\*\* deixaram de ser dois processos separados falando por HTTP. Agora tudo roda \*\*dentro do mesmo processo Django\*\*, na \*\*mesma máquina Linux\*\* e na \*\*mesma pasta\*\*:



\- O sensor (leitura do `eve.json`, gestão do Suricata, firewall e rede) roda como parte do próprio app Django

\- Os eventos são gravados \*\*diretamente no banco\*\*, sem requisições HTTP, sem token de autenticação entre componentes, sem porta extra exposta

\- Um único `venv`, um único `requirements.txt`, um único comando para instalar e rodar



Isso simplifica a instalação (não precisa mais configurar URL do painel, usuário/senha do sensor nem `X-MS-TOKEN`) e elimina a etapa de rede entre Agent e Web — o gateway Linux \*\*é\*\* o servidor MoonShield.



\---



\## 🚀 Módulos e Funcionalidades



| # | Módulo | Descrição | Status |

|---|---|---|---|

| 01 | 🏠 Dashboard Principal | Visão geral de métricas, KPIs e conexões ativas em tempo real | ✅ Ativo |

| 02 | 🚨 IDS / Incidentes (SOC) | Integração com Suricata: alertas ao vivo, triagem, investigação por IP, risk score, correlação DNS/HTTP/TLS | ✅ Ativo |

| 03 | 🌐 DNS \& Rede | Painel AdGuard Home: consultas ao vivo, bloqueio de domínios, regras e feed DNS em tempo real | ✅ Ativo |

| 04 | 🔥 Firewall | Monitoramento de tráfego, gestão de regras iptables/nftables e bloqueio em 1 clique | ✅ Ativo |

| 05 | 🌍 Mapa de Ameaças | Visualização geográfica (Leaflet.js) de origens de ataques via GeoIP em tempo real | 🔧 Planejado |

| 06 | 💻 Diagnóstico de Rede | Ping, traceroute, status do sensor e terminal de diagnóstico integrado | 🔧 Planejado |

| 07 | 🤖 Moon AI | Análise automática de incidentes via Claude API: correlação, mitigações e resumos | 🔧 Planejado |

| 08 | 📄 Relatórios | Geração automática em PDF e CSV consolidando todos os módulos | 🔧 Planejado |

| 09 | 👤 Gestão de Acesso | Perfis com avatares, temas Dark/Light e preferências individuais | ✅ Ativo |



\---



\## ⚙️ Modos de Operação



\### 🔬 Modo Demo — Ambiente Simulado

\- Gera dados realistas (alertas, IPs, eventos DNS) automaticamente

\- Zero configuração — funciona sem infraestrutura real

\- Ideal para demonstrações, apresentações e aulas práticas

\- Disponível imediatamente após a instalação



\### 🛡️ Modo Produção — Ambiente Real

\- Integra com \*\*Suricata IDS\*\*, \*\*AdGuard Home\*\* e \*\*iptables/nftables\*\* reais instalados na própria máquina

\- O sensor roda \*\*em thread/processo interno\*\*, junto com o servidor Django — não precisa de outra máquina

\- Monitoramento contínuo com histórico persistente



\---



\## 🛠️ Stack Tecnológica



| Camada | Tecnologia |

|---|---|

| Backend | Python 3.12 + Django 5.x |

| Banco de Dados | SQLite (dev) · PostgreSQL (produção) |

| Frontend | HTML5, CSS3, JavaScript Vanilla |

| Visualização | Chart.js · Leaflet.js |

| Segurança | Suricata IDS · AdGuard Home · iptables/nftables |

| IA | Claude API (Anthropic) |

| Comunicação interna | Chamadas diretas em Python (sem HTTP/API entre sensor e painel) |



\---



\## 📂 Estrutura do Repositório



```

MoonShield/

│

├── aplicativos/                  # ⚙️  Todos os apps Django

│   ├── autenticacao/             #    Controle de acesso e sessões

│   ├── firewall/                 #    Regras, tráfego e bloqueios (UI + engine)

│   ├── incidentes/                #    Pipeline SOC, correlação e triagem

│   ├── dns/                      #    Monitoramento DNS (AdGuard Home)

│   ├── mapa\_ameacas/             #    Geolocalização e visualização

│   ├── dispositivos/             #    Inventário, scan e diagnóstico

│   ├── relatorios/                #    Geração de PDF/CSV

│   ├── MoonShieldai/             #    Módulo de IA (Claude API)

│   ├── painel/                   #    Dashboard geral

│   ├── configuracoes/            #    Configurações do sistema

│   └── agente/                   # 🛰️  Sensor integrado (ex-MoonShield-Sensor)

│       ├── nucleo/               #    Configuração, monitoramento, utilitários

│       │   ├── configuracao.py

│       │   ├── monitoramento.py  #    Loop do sensor, agora grava direto no banco

│       │   └── utilitarios.py

│       ├── suricata/

│       │   ├── instalador.py     #    Instalação + detecção de topologia

│       │   ├── diagnostico.py    #    Doctor: 15 checks automáticos

│       │   └── regras\_ms.rules   #    MoonShield Ruleset v1 (50 regras)

│       ├── firewall/             #    Conversor e motor de regras iptables/nftables

│       └── rede/                 #    Configuração de DNS, Gateway e VLANs

│

├── config/                       # 🧠  settings.py e roteador mestre

├── media/                        # 📎  Arquivos dinâmicos (avatars, uploads)

├── static/                       # 🎨  Frontend estático (CSS, JS, imagens)

├── templates/                    # 🖥️  Camada HTML

│   └── reutilizaveis/            #    Componentes globais: topbar, sidebar...

│

├── gerenciar.py                  # 🎛️  Orquestrador principal (manage.py customizado)

├── requirements.txt              # 📦  Dependências únicas do projeto

└── .env                          # 🔐  Variáveis de ambiente (não versionar!)

```



> A pasta `agente/` concentra tudo que antes era o repositório `MoonShield-Sensor`, agora como um módulo interno do mesmo app Django — sem servidor HTTP próprio.



\---



\## 💻 Instalação



Como o sensor precisa de acesso ao Suricata, ao `eve.json` e às regras de firewall do sistema, o MoonShield agora roda \*\*inteiramente em Linux\*\*, na máquina que também funciona como gateway.



\### Pré-requisitos



| Requisito | Versão |

|---|---|

| Python | 3.10 ou superior |

| SO | Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / Arch) |

| Privilégios | root (necessário para Suricata, firewall e leitura do `eve.json`) |

| RAM | 4 GB mínimo |



\### 1️⃣ Clonar o repositório



```bash

git clone https://github.com/pedrocavalcanti-dev/moonshield.git

cd MoonShield

```



\### 2️⃣ Criar o ambiente virtual e instalar dependências



```bash

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

```



\### 3️⃣ Aplicar as migrações



```bash

python gerenciar.py migrate

```



> ✅ O sistema cria automaticamente o usuário `moonshield` e exibe as credenciais no terminal. Use-as para fazer login.



\### 4️⃣ Instalar/configurar o Suricata (uma vez, com root)



```bash

sudo .venv/bin/python3 gerenciar.py agente instalar

```



O instalador detecta a topologia de rede (WAN/LAN/MGMT), aplica os patches no `suricata.yaml`, instala as regras Emerging Threats + MoonShield Ruleset e valida com `suricata -T`.



> ⚠️ \*\*Por que `sudo .venv/bin/python3`?\*\* O `sudo python3` puro não enxerga o venv ativado pelo usuário comum. Sempre chame o Python do venv diretamente com `sudo`.



\### 5️⃣ Rodar o MoonShield (painel + sensor juntos)



```bash

sudo .venv/bin/python3 gerenciar.py runserver 0.0.0.0:8000

```



O sensor sobe automaticamente como parte do processo — sem passo extra, sem outra máquina, sem porta adicional. Acesse \*\*http://127.0.0.1:8000\*\*, use as credenciais exibidas no terminal e está dentro. ✅



\---



\## 🔐 Variáveis de Ambiente (opcional)



Crie um arquivo `.env` na raiz do projeto para personalizar:



```env

SECRET\_KEY=sua-chave-secreta-aqui

DEBUG=True

ALLOWED\_HOSTS=127.0.0.1,localhost

EVE\_JSON\_PATH=/var/log/suricata/eve.json

SEVERIDADE\_MINIMA=3

```



⚠️ Nunca versione o `.env` — já está no `.gitignore`.



\---



\## 🛰️ Sensor Integrado — Detalhes



O sensor (antigo `MoonShield-Sensor`) agora vive dentro de `aplicativos/agente/` e é responsável por:



\- Instalar e configurar o \*\*Suricata\*\* automaticamente (detecção de topologia WAN/LAN/MGMT)

\- Monitorar o `eve.json` e \*\*gravar os eventos direto no banco\*\* via ORM do Django (sem HTTP, sem fila externa)

\- Gerenciar as regras de \*\*Firewall\*\* (iptables/nftables) com conversor próprio

\- Configurar \*\*VLANs, DNS e Gateway\*\* da rede monitorada

\- Rodar diagnóstico completo (15 checks automáticos)



```

Máquina Linux (Gateway + MoonShield, mesmo processo)

─────────────────────────────────────────────────────

Suricata → /var/log/suricata/eve.json

&#x20;   └── agente/nucleo/monitoramento.py

&#x20;           └── grava direto no banco (ORM)

&#x20;                   └── Dashboard SOC (mesmo processo Django)

```



Como não existe mais chamada HTTP entre sensor e painel, \*\*não há mais\*\*:

\- URL do MoonShield para configurar

\- Usuário/senha específicos do sensor

\- Header `X-MS-TOKEN`

\- Heartbeat de rede a cada 30s



O status do sensor agora é lido diretamente do processo em execução.



\### 🖥️ Comandos do sensor (via `gerenciar.py`)



```

gerenciar.py agente instalar        # Instala/configura o Suricata

gerenciar.py agente iniciar         # Inicia o monitoramento (ou automático no runserver)

gerenciar.py agente diagnostico     # Roda os 15 checks

gerenciar.py agente firewall        # Abre o gerenciador de regras de firewall

gerenciar.py agente severidade N    # Define severidade mínima (1 a 4)

```



\### 🩺 Diagnóstico — 15 checks automáticos



| Grupo | Checks |

|---|---|

| Sistema | Linux, root |

| Suricata | Binário instalado, `suricata.yaml` encontrado, `suricata -T` válido |

| Configuração | HOME\_NET correto, regras MS instaladas, yaml referencia `ms.rules` |

| Serviço | `systemctl is-active suricata`, interface de captura ativa |

| Logs | `eve.json` existe e cresce, permissão de leitura |

| Topologia | DNS interno configurado, regra de bypass DNS ativa |



\### 🎚️ Severidade mínima



| Opção | Processa |

|---|---|

| `\[1]` Crítico | Só alertas severity 1 |

| `\[2]` Alto | Severity 1 e 2 |

| `\[3]` Médio | Severity 1, 2 e 3 |

| `\[4]` Todos | Sem filtro (padrão) |



✅ Recomendado para produção: `\[3]` Médio — equilibra cobertura e volume.



\### ⚙️ Rodar como serviço systemd (produção)



Como agora é um único processo, o serviço sobe painel + sensor juntos:



```bash

sudo nano /etc/systemd/system/moonshield.service

```



```ini

\[Unit]

Description=MoonShield — Painel + Sensor (processo único)

After=network.target suricata.service



\[Service]

Type=simple

User=root

WorkingDirectory=/opt/MoonShield

ExecStart=/opt/MoonShield/.venv/bin/python gerenciar.py runserver 0.0.0.0:8000

Restart=on-failure

RestartSec=10



\[Install]

WantedBy=multi-user.target

```



```bash

sudo systemctl daemon-reload

sudo systemctl enable moonshield

sudo systemctl start moonshield

sudo systemctl status moonshield

```



\---



\## 🔥 Firewall — Módulo Ativo



O módulo de \*\*Firewall\*\* está totalmente integrado ao mesmo processo:



\- Conversor próprio de regras \*\*iptables/nftables\*\*

\- Leitura e aplicação de regras direto na máquina local (sem sincronização via rede)

\- Bloqueio de IP/porta em \*\*1 clique\*\* direto do dashboard

\- Histórico de regras aplicadas e log de alterações

\- Ajustado e estabilizado na última atualização



\---



\## 🛡️ MoonShield Ruleset v1 — 50 Regras Customizadas



Instaladas em `/var/lib/suricata/rules/moonshield/ms.rules`. SID range reservado: \*\*9900001 – 9900050\*\*



| Grupo | SIDs | O que cobre |

|---|---|---|

| A — Recon / Varredura | 9900001–9900008 | Port scan SYN, ping sweep, host sweep TCP, SNMP, scan de painéis web, UDP multiporta, ARP excessivo, fingerprinting de firewall |

| B — Brute Force / Auth | 9900009–9900016 | SSH, RDP, FTP, SMB, WinRM (5985/5986), Telnet, brute em painel web |

| C — Movimento Lateral | 9900017–9900022 | RPC (135), NetBIOS (139), SMB sweep (445), SQL Server, MySQL, PostgreSQL |

| D — DNS / Policy DNS | 9900023–9900032 | Bypass de DNS público, volume alto de queries, NXDOMAIN em massa, consultas a serviços de IP público, DGA |

| E — P2P / Mineração | 9900033–9900038 | BitTorrent, tracker HTTP, Stratum mining, pools de mineração via DNS, Tor |

| F — Anomalia / Bot | 9900039–9900046 | TCP externo em massa, ICMP tunnel, TLS/DNS beaconing, C2 ports, User-Agent vazio, download de EXE via HTTP, DGA |

| G — TLS / QUIC | 9900047–9900050 | QUIC informativo, SNI com subdomínio numérico, TLS sem SNI, QUIC volume alto |



> As regras usam `detection\_filter` para reduzir falsos positivos. Os limiares (`count`/`seconds`) são ponto de partida — ajuste conforme o tráfego do seu ambiente.



\---



\## 🌐 Requisitos de Rede



Como painel e sensor rodam no mesmo processo, os únicos requisitos de rede são:



\- Porta `8000` liberada para acessar o dashboard (`0.0.0.0:8000` se o acesso for de outra máquina)

\- O `eve.json` precisa ter permissão de leitura:



```bash

sudo chmod 644 /var/log/suricata/eve.json

```



Não há mais necessidade de liberar comunicação entre "sensor" e "painel" — é a mesma máquina, o mesmo processo.



\---



\## 🖥️ Compatibilidade



| Sistema | Suporte |

|---|---|

| Ubuntu 20.04+ | ✅ |

| Debian 11+ | ✅ |

| CentOS / RHEL 8+ | ✅ |

| Arch Linux | ✅ |

| Windows | ⚠️ Só Modo Demo (sem Suricata/firewall reais) |

| Windows WSL | ⚠️ Suporte parcial (sem instalador Suricata) |



\---



\## 🔧 Problemas Comuns



\- `sudo python3` não encontra o Python do venv → use `sudo .venv/bin/python3 gerenciar.py ...`

\- `eve.json` não encontrado → verifique `EVE\_JSON\_PATH` no `.env` e o caminho no `suricata.yaml`

\- Permissão negada no `eve.json` → `sudo chmod 644 /var/log/suricata/eve.json`

\- `suricata -T` falhou após instalação → o backup `suricata.yaml.ms.bak` é restaurado automaticamente

\- Sensor não aparece ativo → confira se o processo foi iniciado com `sudo` (necessário para ler o Suricata)

\- `suricata-update` não encontrado → instale manualmente antes de rodar `gerenciar.py agente instalar`



\---



\## 🔭 Visão Futura



\- \[ ] \*\*Mapa de Ameaças\*\* ao vivo com linhas de ataque animadas (GeoIP + Leaflet.js)

\- \[ ] \*\*IPS\*\* — Suricata em modo inline com bloqueio automático via iptables

\- \[ ] \*\*Moon AI\*\* — análise automática de incidentes via Claude API

\- \[ ] \*\*Relatórios PDF\*\* gerados automaticamente por período

\- \[ ] \*\*MoonShield Attack\*\* — simulação controlada para cenários Blue Team vs Red Team (exclusivamente educacional, ambiente isolado)

\- \[ ] \*\*MoonGroup\*\* — versão SaaS multi-tenant para MSPs e instituições de ensino



\---



\## 📄 Licença



Distribuído sob a licença \*\*MIT\*\*. Consulte o arquivo `LICENSE` para mais detalhes.



\---



<div align="center">



\*\*Desenvolvido com 🛡️ por Pedro Cavalcanti\*\*



Técnico em Redes de Computadores · Senac São Paulo · 2026



\*Para operações táticas de Blue Team e ensino prático de segurança de redes.\*



</div>

