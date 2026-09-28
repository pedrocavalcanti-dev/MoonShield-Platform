# MoonShield ISO 0.1.0-alpha.2

A ISO Alpha 2 transforma o Debian Installer no motor interno de instalação da
MoonShield Appliance. O fluxo normal é apresentado em português do Brasil e não
cria usuário Linux humano nem senha padrão.

## Experiência esperada

```text
Boot
→ MOONSHIELD — Appliance de Segurança de Rede
→ Instalar MoonShield
→ seleção segura do disco
→ confirmação explícita digitando INSTALAR
→ instalação mínima automatizada do Debian 13
→ late-command prepara o bootstrap offline
→ reboot
→ Preparando sua appliance...
→ deploy/install.sh --offline ... --final-iso
→ moonshield-install-check
→ MoonShield Console
→ First Setup web
```

O item `Opções avançadas` mantém um caminho técnico com prioridade baixa do
Debian Installer para diagnóstico. O fluxo normal usa `auto=true` e
`priority=critical`.

## Segurança do disco

A ISO não escolhe silenciosamente o primeiro `/dev/sdX`. O script
`installer/select-disk.sh` é executado por `partman/early_command`, quando os
discos já estão visíveis para o Debian Installer. Ele:

- lista discos válidos;
- ignora loop, RAM, CD-ROM e mídia marcada como removível;
- mostra device, modelo e tamanho;
- exige seleção numérica;
- exige a palavra `INSTALAR` antes de autorizar a operação destrutiva;
- grava o mesmo device em `partman-auto/disk` e `grub-installer/bootdev`.

Depois dessa confirmação, Partman pode particionar automaticamente o disco
selecionado.

## Preseed embutido no initrd

O builder extrai `/install.amd/initrd.gz`, detecta sua compressão, inclui:

```text
/preseed.cfg
/moonshield/select-disk.sh
```

e reconstrói o initrd em staging. A ISO Debian original nunca é alterada.

Depois de gerar a ISO final, o builder extrai novamente o initrd da mídia final
e confirma a presença desses arquivos. Se a prova falhar, o build é abortado.

O preseed elimina o fluxo normal de:

- usuário/senha Linux;
- senha root;
- tasksel;
- desktop;
- popularity-contest;
- mirror APT;
- media scan adicional;
- escolha manual do target do GRUB.

Defaults:

```text
Locale:       pt_BR.UTF-8
Teclado:      br
Timezone:     America/Sao_Paulo
Hostname:     moonshield
Domain:       local
Rede inicial: DHCP
```

## Firstboot

`late-command.sh` copia release e offline bundle para:

```text
/var/lib/moonshield-iso-bootstrap/
```

Também instala uma console gate independente do Django e o serviço one-shot de
firstboot. TTY1 é mascarado para getty antes do primeiro reboot; assim uma falha
não cai em `Debian login:`.

Arquivos principais:

```text
firstboot/moonshield-firstboot.py
firstboot/moonshield-console-gate.py
firstboot/moonshield-iso-firstboot.service
firstboot/moonshield-iso-console-gate.service
```

A gate mostra progresso real por fases, sem porcentagens falsas. O installer é
executado com:

```bash
/bin/bash /var/lib/moonshield-iso-bootstrap/release/deploy/install.sh \
  --offline /var/lib/moonshield-iso-bootstrap/offline-bundle \
  --final-iso
```

Em seguida o healthcheck gerenciado roda novamente antes do handoff para o
console local.

### Sucesso

Somente após installer + healthcheck + inicialização do console é criado:

```text
/var/lib/moonshield/.installation-complete
```

O firstboot é desabilitado e o payload duplicado de bootstrap é removido.

### Falha

É criado:

```text
/var/lib/moonshield/.installation-failed
```

Log persistente:

```text
/var/log/moonshield/firstboot-install.log
```

O firstboot é desabilitado para impedir loop de reinstalação. A TTY1 permanece
na tela MoonShield de falha. F12 abre o fluxo RSA challenge-response de
manutenção; não existe senha universal de fallback.

## Builder

Requisitos do builder:

- Debian 13 amd64;
- bash;
- xorriso;
- cpio;
- gzip;
- openssl;
- python3;
- dpkg/coreutils;
- xz ou zstd apenas se a ISO base usar esse formato de initrd.

### Debian base autenticada

Versão fixa:

```text
Debian 13.7.0 amd64 netinst
```

SHA256 autenticado e fixado no manifest:

```text
a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355
```

Arquivo esperado:

```text
debian-13.7.0-amd64-netinst.iso
```

Não trocar por URLs `current`/`latest` sem novo processo de validação.

## Chave de manutenção

Antes de criar a release tree, disponibilize **somente a chave pública** em:

```text
deploy/console/maintenance_public.pem
```

Ela deve ser RSA >= 3072 bits.

A chave privada nunca entra em:

- Git;
- release tree;
- offline bundle;
- ISO.

## Gerar release tree

A partir da raiz do repositório:

```bash
sudo bash deploy/scripts/build-release-tree.sh \
  /var/tmp/moonshield-alpha2-release
```

## Offline bundle

Se as dependências não mudaram em relação ao bundle já validado, ele pode ser
reutilizado. Para gerar um novo:

```bash
sudo bash deploy/scripts/prepare-offline-bundle.sh \
  /opt/moonshield-offline-bundle
```

## Gerar ISO

Exemplo usando os paths do builder MoonShield:

```bash
sudo bash deploy/iso/build-iso.sh \
  /opt/moonshield-iso-base/debian-13.7.0-amd64-netinst.iso \
  /var/tmp/moonshield-alpha2-release \
  /opt/moonshield-offline-bundle
```

Output:

```text
build/iso/MoonShield-0.1.0-alpha.2-amd64.iso
build/iso/MoonShield-0.1.0-alpha.2-amd64.iso.sha256
```

Volume ID:

```text
MOONSHIELD_ALPHA2
```

O builder não sobrescreve uma saída existente.

## Validações automáticas do builder

Antes de publicar a ISO, o script verifica:

- hash da ISO Debian;
- release tree;
- ausência de material de chave privada;
- RSA pública >= 3072 bits;
- checksum do offline bundle;
- boot BIOS;
- boot UEFI;
- initrd reconstruído;
- preseed no initrd;
- seletor de disco no initrd;
- menus em português;
- late-command;
- firstboot;
- release payload;
- offline bundle;
- BUILD-INFO;
- volume ID Alpha 2;
- checksum final da mídia.

## Teste obrigatório em VM limpa

Não considere Alpha 2 validada apenas por testes estáticos. Use uma VM
descartável com disco vazio.

Checklist:

1. BIOS: menu MoonShield aparece.
2. UEFI: menu MoonShield aparece.
3. `Instalar MoonShield` é a opção normal.
4. Nenhum usuário/senha Debian é solicitado.
5. Nenhum tasksel/popularity/mirror é solicitado.
6. MoonShield lista os discos.
7. Nenhum disco é apagado sem `INSTALAR`.
8. Particionamento conclui automaticamente depois da confirmação.
9. GRUB usa o mesmo disco selecionado.
10. Reboot não mostra `Debian login:`.
11. TTY1 mostra `Preparando sua appliance...`.
12. Installer offline conclui.
13. Healthcheck conclui sem FAIL.
14. MoonShield Console assume TTY1.
15. First Setup web fica acessível quando houver DHCP.
16. Segundo reboot volta ao MoonShield Console.
17. TTY2-6 estão bloqueados no modo final.
18. SSH está desabilitado por padrão.
19. F12 exige resposta RSA válida.

## Logs úteis

Durante/apos a instalação:

```text
/var/log/moonshield/late-command.log
/var/log/moonshield/firstboot-install.log
```

Depois da instalação:

```bash
/usr/local/sbin/moonshield-install-check
systemctl status moonshield-console.service
systemctl status moonshield-web.service
```
