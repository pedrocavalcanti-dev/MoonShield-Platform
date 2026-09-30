# MoonShield 0.1.0-alpha.2 — Final Polish v3

Este pacote consolida os fixes funcionais da Alpha 2 e a camada visual final do
instalador/appliance.

## Funcional

- preseed carregado da mídia remasterizada;
- nenhuma conta humana criada pelo Debian Installer;
- seleção de disco via cdebconf com confirmação destrutiva;
- late-command fail-closed;
- bundle offline formato 2 / fechamento completo;
- firstboot com uma tentativa de reparo controlada;
- console gate protegida e sem login Debian;
- transição de sucesso sem corrida entre gate e `moonshield-console.service`;
- GRUB instalado renomeado para MOONSHIELD.

## Visual

- BIOS preto/roxo em ASCII seguro;
- UEFI GRUB preto/roxo sem dependência de bitmap;
- Debian Installer em `newt` + tema `dark` suportado oficialmente;
- modo compatível de vídeo para máquinas problemáticas;
- firstboot com painel, spinner, progresso, estados e tela de falha segura;
- console final com identidade MoonShield.

## Princípio de compatibilidade

A personalização evita substituir cdebconf/newt por um fork próprio e não exige
GPU. O objetivo é aparência própria sem transformar branding em requisito para
o instalador funcionar.
