# MoonShield 0.1.0-alpha.2 — relatório de validação estática

## Resultado

Todos os checks estáticos executados no pacote final passaram:

- `bash -n` em `build-iso.sh`, `late-command.sh` e `installer/select-disk.sh`;
- `python -m py_compile` no firstboot, console gate e console local;
- `debconf-set-selections --checkonly` no `preseed.cfg`;
- `systemd-analyze verify` nas duas units de bootstrap;
- verificação de whitespace equivalente a `git diff --check`;
- scan por `shell=True`, `os.system`, `eval`, `chmod 777`, `curl -k`,
  `wget --no-check-certificate` e material PEM de private key;
- presença dos arquivos obrigatórios Alpha 2;
- SHA256 autenticado da ISO Debian 13.7.0 fixado no manifest.

## O que ainda exige validação real

Teste estático não substitui boot real. Antes de marcar Alpha 2 como aprovada,
gerar a ISO no builder Debian 13 amd64 e instalar em VMs descartáveis:

1. BIOS + disco vazio;
2. UEFI + disco vazio;
3. cenário com dois discos para validar a seleção;
4. reboot após sucesso;
5. cenário controlado de falha de firstboot;
6. segundo reboot depois da instalação concluída.

O resultado esperado está documentado em `deploy/iso/README.md`.
