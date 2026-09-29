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
