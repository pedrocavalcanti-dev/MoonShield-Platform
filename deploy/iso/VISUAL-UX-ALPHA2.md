# MoonShield Alpha 2 — Visual / UX de boot e instalação

Objetivo: entregar uma experiência de appliance consistente sem introduzir
dependências gráficas frágeis no caminho de instalação.

## Camadas de identidade

1. **BIOS / ISOLINUX**
   - Fundo preto e seleção roxa `#5B5AF3`.
   - Textos ASCII para evitar caracteres `�` em firmwares/codepages antigos.
   - Entrada normal, modo compatível de vídeo e diagnóstico.

2. **UEFI / GRUB da ISO**
   - Tema textual MoonShield com preto, branco, `#5B5AF3` e `#9595FB`.
   - Nenhuma imagem externa obrigatória: o menu continua renderizando mesmo se
     módulos gráficos opcionais não estiverem disponíveis.

3. **Debian Installer (motor interno)**
   - `DEBIAN_FRONTEND=newt` + `theme=dark`.
   - O tema `dark` é o caminho oficialmente suportado pelo Debian Installer e
     evita manter um fork/udeb próprio do cdebconf, preservando compatibilidade.
   - As telas específicas de armazenamento usam templates `MOONSHIELD`.

4. **GRUB do sistema instalado**
   - `GRUB_DISTRIBUTOR="MOONSHIELD"`.
   - Menu curto de 2 segundos.
   - Tema textual MoonShield e fallback textual se `gfxterm` não estiver disponível.
   - `systemd.show_status=false` para não vazar ruído visual do sistema base em
     boots normais; falhas de bootstrap são apresentadas pela gate MoonShield.

5. **First boot / bootstrap**
   - Tela curses preta/roxa responsiva (80x25 ou maior).
   - Spinner, barra percentual e estados por etapa.
   - Estados: provisionando, sucesso e falha segura.
   - F12 de manutenção somente em falha, protegido por challenge/response.
   - Sem prompt de login Debian.

6. **Console final**
   - Cabeçalho e seleção alinhados à paleta MoonShield.
   - Continua texto-only para funcionar em qualquer console Linux comum.

## Compatibilidade

O fluxo visual evita PNG/JPEG obrigatórios no boot e usa somente componentes já
presentes no Debian netinst/GRUB/ISOLINUX. Em máquinas com problemas de
framebuffer, a opção **Modo compativel de video** usa `fb=false`, `vga=normal` e
`nomodeset`.

Não é possível garantir toda GPU/firmware existente, por isso o instalador
mantém fallback textual e uma entrada explícita de compatibilidade.
