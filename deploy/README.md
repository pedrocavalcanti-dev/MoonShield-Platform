# MoonShield Appliance deployment

Este diretório contém o installer reproduzível da MoonShield Appliance e o
pipeline da ISO baseada em Debian 13 amd64.

## Componentes

```text
deploy/install.sh                   installer da appliance
deploy/lib/                         módulos do installer
deploy/systemd/                     serviços gerenciados
deploy/console/                     console local protegida
deploy/scripts/                     release, bundle e healthcheck
deploy/iso/                         MoonShield Appliance ISO
deploy/nginx/                       reverse proxy
deploy/manifests/                   versões/dependências
```

## Installer em Debian já instalado

```bash
sudo bash deploy/install.sh --offline /caminho/do/offline-bundle
```

`--final-iso` é reservado à instalação da mídia final. Ele aplica a política de
appliance: console em TTY1, TTY2-6 bloqueados, SSH desabilitado e chave pública
de manutenção obrigatória.

Não use `--final-iso` na VM de desenvolvimento.

## MoonShield ISO

A versão alvo atual é:

```text
MoonShield 0.1.0-alpha.2
```

A experiência normal da mídia é em português:

```text
Boot MoonShield
→ selecionar e confirmar disco
→ Debian base automatizado
→ reboot
→ provisionamento offline MoonShield
→ healthcheck
→ console local
→ First Setup web
```

Documentação completa:

```text
deploy/iso/README.md
```

## Segurança

Nunca versionar:

- `.env`;
- SECRET_KEY;
- senha PostgreSQL;
- tokens;
- private maintenance key;
- dumps de banco;
- logs de runtime.

Apenas `maintenance_public.pem` pode ser embarcada na release/ISO.

O usuário `moonshield` é uma conta de serviço com `/usr/sbin/nologin`. Nenhuma
conta Linux humana ou senha universal é criada pelo fluxo da ISO.

## Fronteira de validação

Windows é adequado para edição e testes estáticos. O comportamento real de
systemd, NetworkManager, nftables, Suricata, AdGuard e boot BIOS/UEFI precisa ser
validado em Debian 13 amd64 e, por fim, em VM limpa criada pela ISO.
