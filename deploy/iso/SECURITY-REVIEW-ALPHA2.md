# MoonShield Alpha 2 — revisão de segurança e robustez da ISO

## Escopo
Revisão estática da cadeia de build, boot BIOS/UEFI, Debian Installer, preseed, seleção de disco, late-command, firstboot, console local e manutenção protegida.

## Decisões aplicadas nesta revisão
- Adicionado `noshell BOOT_DEBUG=0` às entradas normais e compatíveis do Debian Installer.
- Removida a entrada `Opcoes avancadas / diagnostico` da mídia final para reduzir superfície e evitar acesso desnecessário ao menu de baixo nível do d-i.
- Explicitado `finish-install/keep-consoles=false` no preseed.
- Mantido `tty4` para logs do Debian Installer; `noshell` bloqueia shells interativos em `tty2`/`tty3` sem retirar o console de logs.
- Alterado `systemd.show_status=false` para `systemd.show_status=auto`: boot normal continua limpo, mas falhas precoces podem ser exibidas.
- Preservação best-effort de `syslog`, `partman`, `hardware-summary` e `cdebconf` do d-i em `/var/log/moonshield/installer/` com modo 0600.
- Builder passa a falhar se `noshell` for removido, se uma entrada avançada voltar, se `keep-consoles=false` sumir ou se a preservação de logs desaparecer.

## Controles já presentes e mantidos
- ISO Debian base fixada por SHA-256.
- Offline bundle com SHA256SUMS, `BundleFormat=2` e fechamento completo de dependências.
- Release rejeita `.env`, logs, SQLite, caches Python, testes e qualquer chave privada detectável.
- Chave pública de manutenção RSA >= 3072 bits; chave privada não entra na release/ISO.
- Root sem senha utilizável e nenhum usuário humano padrão.
- SSH desabilitado no modo final; autenticação por senha/root proibida na política instalada.
- TTY2–TTY6 mascarados no sistema final; TTY1 é ocupado pela gate/console MoonShield.
- F12 exige challenge aleatório + assinatura RSA antes de abrir shell root; resposta não é senha estática e challenge não é reutilizável.
- Logs de bootstrap e instalação têm permissões restritas.
- Firstboot é fail-closed: falha mantém gate MoonShield e não libera prompt Debian.

## Riscos residuais aceitos na Alpha 2
1. **Acesso físico não é uma fronteira de segurança completa.** Quem controla firmware/boot pode iniciar outra mídia ou alterar a linha do kernel. `noshell` reduz exposição acidental durante o instalador, mas não substitui senha de firmware, bloqueio de boot externo, Secure Boot e proteção física.
2. **Secure Boot precisa de teste explícito.** A ISO preserva binários/estrutura Debian, mas a matriz Alpha 2 deve testar UEFI com Secure Boot ligado antes de declarar suporte.
3. **A autenticidade da ISO base depende do hash pinado ter sido obtido de fonte autenticada.** Evolução futura: validar `SHA256SUMS` + assinatura OpenPGP Debian no builder, mantendo fingerprint pinado.
4. **Modo de manutenção concede root após autorização.** Isto é intencional. O private key correspondente deve ser tratado como credencial de alto impacto e armazenado fora da appliance/ISO.
5. **Logs podem conter topologia e nomes internos.** Permanecem root-only e devem ser sanitizados antes de compartilhamento externo.

## Matriz mínima antes de release
- BIOS/Legacy: instalação completa em disco vazio.
- UEFI sem Secure Boot: instalação completa.
- UEFI com Secure Boot: teste separado e documentado.
- VirtualBox + pelo menos uma segunda VM (VMware/Hyper-V/KVM).
- 1 NIC e 2 NICs.
- Disco SATA/SCSI/NVMe virtual.
- Modo de vídeo normal e modo compatível.
- Falha proposital do bundle: deve cair na gate, sem login Debian.
- F12: assinatura inválida recusada; assinatura válida abre manutenção; sair retorna à console.
- Alt+F2/Alt+F3 durante instalação normal: nenhum shell interativo.
- Alt+F4: logs continuam acessíveis.
- Reboot pós-instalação: GRUB MoonShield -> firstboot -> console MoonShield.
- SSH: inativo e desabilitado após provisioning.
- `moonshield-install-check`: todos os checks críticos OK.

## Critério de liberação
Alpha 2 só deve ser marcada como instalável quando BIOS e UEFI completarem o fluxo sem intervenção inesperada, o firstboot concluir, o healthcheck ficar verde, nenhum login Debian ficar exposto e os testes de falha/recuperação acima passarem.
