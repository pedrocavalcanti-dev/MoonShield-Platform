# MoonShield Alpha 2 — checklist de validação

## Build

- Builder Debian 13 amd64.
- ISO Debian base com SHA-256 autenticado no manifest.
- Release tree sem `.env`, logs, SQLite, testes, `__pycache__` ou chave privada.
- `maintenance_public.pem` presente e RSA >= 3072 bits.
- Offline bundle validado por `SHA256SUMS`.
- `preseed.cfg`, `select-disk.sh` e `moonshield-disk.templates` presentes no initrd final.
- BIOS e UEFI preservados.
- Volume final `MOONSHIELD_ALPHA2`.

## Fluxo esperado em VM descartável

1. Boot mostra `Instalar MoonShield`.
2. Rede inicial via DHCP.
3. Não pergunta nome de utilizador, login ou senha.
4. Ao iniciar o particionador, o próprio frontend do Debian Installer mostra:
   - seleção de disco MoonShield com dispositivo, modelo e tamanho;
   - confirmação destrutiva explícita, iniciando em `Não`.
5. O seletor não usa `openvt`, `chvt` ou leitura direta de TTY.
6. Após confirmar, `partman-auto/disk` e `grub-installer/bootdev` recebem o mesmo disco.
7. Particionamento e instalação seguem automaticamente.
8. Reinicia, ejeta ISO e executa o firstboot MoonShield.

## Segurança do seletor de disco

- Exclui `/dev/sr*`, loop, ram, floppy, device-mapper e a mídia montada em `/cdrom`.
- Exclui dispositivos marcados como removíveis pelo kernel.
- Revalida o dispositivo imediatamente antes de configurar Partman/GRUB.
- Qualquer falha no frontend Debconf interrompe a instalação em vez de escolher um disco automaticamente.
- A confirmação destrutiva inicia em `false` e é reapresentada em cada tentativa.

## Diagnóstico no Debian Installer

Console de log normalmente: `Alt+F4` (ou Host Key + F4 no VirtualBox).
Shell normalmente: `Alt+F2` (ou Host Key + F2).

Logs úteis:

```sh
grep -i moonshield /var/log/syslog | tail -100
cat /tmp/moonshield-selected-disk 2>/dev/null || true
```

Se o seletor falhar, execute apenas para diagnóstico:

```sh
/bin/sh -x /moonshield/select-disk.sh
```

## Late-command / primeiro boot

- [ ] `late-command.sh` não usa `sha256sum --status`/`-s` no ambiente d-i.
- [ ] TTY1-6 ficam mascarados antes da cópia do payload grande.
- [ ] `moonshield-iso-console-gate.service` e `moonshield-iso-firstboot.service` ficam habilitados em `multi-user.target.wants`.
- [ ] A chave pública de manutenção é copiada para `/etc/moonshield/support/maintenance_public.pem` ainda no late-command.
- [ ] Em falha simulada após preparar a gate, o próximo boot não expõe `login:` Debian e mostra estado de falha MoonShield.
- [ ] Em sucesso, o reboot mostra `Preparando sua appliance...` e o firstboot valida `SHA256SUMS` antes de executar `deploy/install.sh`.

## Alpha 2 - hardening final de firstboot / branding

- O bundle offline final deve declarar `BundleFormat=2` e `DependencyClosure=full`.
- `prepare-offline-bundle.sh` resolve os pacotes com um estado dpkg vazio para nao omitir dependencias que ja existiam no builder.
- O firstboot faz no maximo duas tentativas automaticas: instalacao normal e um unico retry `--repair` apos reconciliar `dpkg`/APT sem rede.
- A etapa atual do installer e persistida em `/var/lib/moonshield/install-stage` e aparece no diagnostico de falha.
- Em falha, TTY1 permanece na gate MoonShield; TTY1-6 nao liberam login Debian.
- O sistema instalado recebe branding GRUB/issue MoonShield; o menu GRUB normal fica oculto com timeout zero.
- Logs principais: `/var/log/moonshield/firstboot-install.log` e `/var/log/moonshield/install.log`.

## Aceite visual / UX

- BIOS: fundo escuro, seleção roxa e nenhum caractere `�`.
- UEFI: título `MOONSHIELD`, subtítulo `NETWORK SECURITY APPLIANCE` e menu central.
- Entrada `Modo compativel de video` presente em BIOS e UEFI.
- Debian Installer inicia com frontend newt no tema `dark`.
- Seletor de disco usa título `MOONSHIELD // ARMAZENAMENTO`.
- GRUB instalado não mostra `Debian GNU/Linux` como rótulo principal.
- Após reboot, o bootstrap mostra `MOONSHIELD // PREPARANDO SUA APPLIANCE` em TTY1.
- Em sucesso, a gate mostra `APPLIANCE PRONTA` antes de entregar o TTY ao console.
- Em falha, mostra `MODO SEGURO`, etapa, logs e F12; nenhum login Debian fica exposto.
- Console final mantém cabeçalho `MOONSHIELD` e seleção roxa quando cores estão disponíveis.

## Segurança do instalador / consoles

- Boot normal e modo compatível devem conter `noshell BOOT_DEBUG=0`.
- `Alt+F2` e `Alt+F3` não devem abrir shell interativo durante o d-i.
- `Alt+F4` deve continuar exibindo o log do instalador.
- A mídia final não deve oferecer entrada `moonshield-advanced`.
- Após o reboot, TTY2–TTY6 não devem oferecer login.
- O modo F12 deve negar assinatura inválida e somente liberar shell após challenge/response válido.
- Verificar `/var/log/moonshield/installer/` após instalação para confirmar preservação best-effort dos logs do d-i.
