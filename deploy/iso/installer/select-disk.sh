#!/bin/sh
set -eu

TTY=/dev/tty1
[ -c "$TTY" ] || TTY=/dev/console
STATE=/tmp/moonshield-selected-disk

PURPLE='\033[1;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

out() { printf '%b\n' "$*" >"$TTY"; }
clear_screen() { printf '\033[2J\033[H' >"$TTY"; }
fail() {
    clear_screen
    out "${PURPLE}${BOLD}MOONSHIELD${RESET}"
    out ""
    out "ERRO NA SELEÇÃO DO DISCO"
    out ""
    out "$*"
    out ""
    out "A instalação foi interrompida para evitar alterações em um disco incorreto."
    out "Reinicie o equipamento e tente novamente."
    exit 1
}

set_debconf() {
    key="$1"
    value="$2"
    command -v debconf-set >/dev/null 2>&1 || fail "O Debian Installer não disponibilizou debconf-set."
    debconf-set "$key" "$value"
}

base_name() {
    dev="$1"
    basename "$dev"
}

is_removable() {
    name="$(base_name "$1")"
    [ -r "/sys/block/$name/removable" ] && [ "$(cat "/sys/block/$name/removable" 2>/dev/null || printf 0)" = 1 ]
}

model_for() {
    name="$(base_name "$1")"
    model=""
    if [ -r "/sys/block/$name/device/model" ]; then
        model="$(tr -d '\000' < "/sys/block/$name/device/model" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    fi
    [ -n "$model" ] || model="Disco $name"
    printf '%s' "$model"
}

size_for() {
    name="$(base_name "$1")"
    sectors=0
    [ -r "/sys/block/$name/size" ] && sectors="$(cat "/sys/block/$name/size" 2>/dev/null || printf 0)"
    case "$sectors" in ''|*[!0-9]*) sectors=0 ;; esac
    bytes=$((sectors * 512))
    if [ "$bytes" -ge 1073741824 ]; then
        tenths=$((bytes * 10 / 1073741824))
        printf '%s,%s GiB' $((tenths / 10)) $((tenths % 10))
    elif [ "$bytes" -ge 1048576 ]; then
        printf '%s MiB' $((bytes / 1048576))
    else
        printf '%s bytes' "$bytes"
    fi
}


installer_media_disk() {
    source_dev="$(awk '$2 == "/cdrom" {print $1; exit}' /proc/mounts 2>/dev/null || true)"
    case "$source_dev" in
        /dev/*) ;;
        *) return 0 ;;
    esac
    name="$(basename "$source_dev")"
    sys="$(readlink -f "/sys/class/block/$name" 2>/dev/null || true)"
    [ -n "$sys" ] || return 0
    if [ -r "/sys/class/block/$name/partition" ]; then
        printf '/dev/%s' "$(basename "$(dirname "$sys")")"
    else
        printf '/dev/%s' "$name"
    fi
}

INSTALL_MEDIA_DISK="$(installer_media_disk)"

valid_disk() {
    dev="$1"
    [ -b "$dev" ] || return 1
    [ -z "$INSTALL_MEDIA_DISK" ] || [ "$dev" != "$INSTALL_MEDIA_DISK" ] || return 1
    case "$dev" in
        /dev/loop*|/dev/ram*|/dev/sr*|/dev/fd*) return 1 ;;
    esac
    is_removable "$dev" && return 1
    return 0
}

collect_disks() {
    if command -v list-devices >/dev/null 2>&1; then
        list-devices disk 2>/dev/null || true
    else
        for sysdev in /sys/block/*; do
            [ -e "$sysdev" ] || continue
            printf '/dev/%s\n' "$(basename "$sysdev")"
        done
    fi
}

if [ -s "$STATE" ]; then
    selected="$(cat "$STATE" 2>/dev/null || true)"
    if valid_disk "$selected"; then
        set_debconf partman-auto/disk "$selected"
        set_debconf grub-installer/bootdev "$selected"
        exit 0
    fi
fi

DISKS=""
for dev in $(collect_disks); do
    if valid_disk "$dev"; then
        DISKS="${DISKS}${dev}\n"
    fi
done
DISKS="$(printf '%b' "$DISKS" | sed '/^$/d')"
COUNT="$(printf '%s\n' "$DISKS" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$COUNT" -gt 0 ] || fail "Nenhum disco de instalação válido foi encontrado."

while :; do
    clear_screen
    out "${PURPLE}${BOLD}MOONSHIELD${RESET}"
    out "${BOLD}Appliance de Segurança de Rede${RESET}"
    out ""
    out "${BOLD}Selecionar disco de instalação${RESET}"
    out ""
    index=1
    printf '%s\n' "$DISKS" | while IFS= read -r dev; do
        [ -n "$dev" ] || continue
        out "  ${PURPLE}${BOLD}$index.${RESET} $(model_for "$dev")"
        out "     $(size_for "$dev")   ${DIM}$dev${RESET}"
        out ""
        index=$((index + 1))
    done
    out "Todos os dados do disco escolhido serão apagados."
    out ""
    printf 'Digite o número do disco e pressione Enter: ' >"$TTY"
    IFS= read -r choice <"$TTY" || fail "Não foi possível ler a seleção do disco."
    case "$choice" in ''|*[!0-9]*) continue ;; esac
    [ "$choice" -ge 1 ] 2>/dev/null || continue
    [ "$choice" -le "$COUNT" ] 2>/dev/null || continue
    selected="$(printf '%s\n' "$DISKS" | sed -n "${choice}p")"
    valid_disk "$selected" || fail "O disco selecionado deixou de estar disponível."

    clear_screen
    out "${PURPLE}${BOLD}MOONSHIELD${RESET}"
    out "${BOLD}Confirmar instalação${RESET}"
    out ""
    out "MoonShield será instalado em:"
    out ""
    out "  ${BOLD}$(model_for "$selected")${RESET}"
    out "  $(size_for "$selected")"
    out "  $selected"
    out ""
    out "${BOLD}ATENÇÃO: TODOS OS DADOS DESTE DISCO SERÃO APAGADOS.${RESET}"
    out ""
    printf 'Digite INSTALAR para confirmar ou CANCELAR para voltar: ' >"$TTY"
    IFS= read -r confirm <"$TTY" || fail "Não foi possível ler a confirmação."
    case "$confirm" in
        INSTALAR|instalar|Instalar)
            printf '%s\n' "$selected" >"$STATE"
            chmod 0600 "$STATE" 2>/dev/null || true
            set_debconf partman-auto/disk "$selected"
            set_debconf grub-installer/bootdev "$selected"
            clear_screen
            out "${PURPLE}${BOLD}MOONSHIELD${RESET}"
            out ""
            out "Disco confirmado: ${BOLD}$selected${RESET}"
            out "Preparando a instalação do sistema base..."
            sleep 1
            exit 0
            ;;
        CANCELAR|cancelar|Cancelar)
            continue
            ;;
        *)
            continue
            ;;
    esac
done
