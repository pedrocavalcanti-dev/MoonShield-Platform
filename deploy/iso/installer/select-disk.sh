#!/bin/sh
# MoonShield Alpha 2 - disk selector for Debian Installer
# Uses the installer cdebconf frontend instead of direct TTY/VT access.
set -e

STATE=/tmp/moonshield-selected-disk
TEMPLATES=/moonshield/moonshield-disk.templates
OWNER=moonshield-installer
DEBCONF_READY=0

log_msg() {
    if command -v logger >/dev/null 2>&1; then
        logger -t moonshield-select-disk -- "$*" 2>/dev/null || true
    fi
}

base_name() {
    basename "$1"
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
    # Debconf select choices are comma separated. Keep dynamic labels comma-free.
    printf '%s' "$model" | tr ',' ' '
}

size_for() {
    name="$(base_name "$1")"
    sectors=0
    [ -r "/sys/block/$name/size" ] && sectors="$(cat "/sys/block/$name/size" 2>/dev/null || printf 0)"
    case "$sectors" in ''|*[!0-9]*) sectors=0 ;; esac
    bytes=$((sectors * 512))
    if [ "$bytes" -ge 1073741824 ]; then
        tenths=$((bytes * 10 / 1073741824))
        printf '%s.%s GiB' $((tenths / 10)) $((tenths % 10))
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
        /dev/loop*|/dev/ram*|/dev/sr*|/dev/fd*|/dev/dm-*) return 1 ;;
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

load_debconf_templates() {
    [ -f "$TEMPLATES" ] || return 1

    if command -v debconf-loadtemplate >/dev/null 2>&1; then
        debconf-loadtemplate "$OWNER" "$TEMPLATES" >/dev/null 2>&1 || return 1
    elif [ -x /usr/lib/cdebconf/debconf-loadtemplate ]; then
        /usr/lib/cdebconf/debconf-loadtemplate "$OWNER" "$TEMPLATES" >/dev/null 2>&1 || return 1
    else
        return 1
    fi

    [ -r /usr/share/debconf/confmodule ] || return 1
    # confmodule intentionally configures file descriptors used by the active d-i frontend.
    # shellcheck disable=SC1091
    . /usr/share/debconf/confmodule
    DEBCONF_READY=1
    db_capb backup 2>/dev/null || true
    # partman may leave a progress dialog active while early_command runs.
    # Stop it before presenting MoonShield questions through the same frontend.
    db_progress STOP >/dev/null 2>&1 || true
    return 0
}

show_error() {
    message="$1"
    log_msg "ERRO: $message"
    if [ "$DEBCONF_READY" = 1 ]; then
        db_subst moonshield/error ERROR "$message" >/dev/null 2>&1 || true
        db_fset moonshield/error seen false >/dev/null 2>&1 || true
        db_input critical moonshield/error >/dev/null 2>&1 || true
        db_go >/dev/null 2>&1 || true
    fi
}

fail() {
    show_error "$*"
    exit 1
}

set_debconf_value() {
    key="$1"
    value="$2"
    if [ "$DEBCONF_READY" = 1 ]; then
        db_set "$key" "$value" || fail "Não foi possível configurar $key."
    elif command -v debconf-set >/dev/null 2>&1; then
        debconf-set "$key" "$value" || fail "Não foi possível configurar $key."
    else
        fail "O Debian Installer não disponibilizou acesso ao banco Debconf."
    fi
}

apply_selected_disk() {
    selected="$1"
    valid_disk "$selected" || fail "O disco selecionado deixou de estar disponível: $selected"
    set_debconf_value partman-auto/disk "$selected"
    set_debconf_value grub-installer/bootdev "$selected"
    printf '%s\n' "$selected" >"$STATE"
    chmod 0600 "$STATE" 2>/dev/null || true
    log_msg "Disco aplicado ao Partman e GRUB: $selected"
}

load_debconf_templates || fail "O Debian Installer não disponibilizou o frontend Debconf necessário para selecionar o disco com segurança."

# Build dynamic choices only from non-removable whole disks, excluding install media.
CHOICES=""
FIRST_CHOICE=""
COUNT=0
for dev in $(collect_disks); do
    valid_disk "$dev" || continue
    model="$(model_for "$dev")"
    size="$(size_for "$dev")"
    choice="$dev | $model | $size"
    if [ -z "$CHOICES" ]; then
        CHOICES="$choice"
        FIRST_CHOICE="$choice"
    else
        CHOICES="$CHOICES, $choice"
    fi
    COUNT=$((COUNT + 1))
    log_msg "Disco candidato: $dev model='$model' size='$size'"
done

[ "$COUNT" -gt 0 ] || fail "Nenhum disco interno válido foi encontrado para instalar o MoonShield."
log_msg "$COUNT disco(s) válido(s) detectado(s)."

while :; do
    db_settitle moonshield/disk-title || true
    db_subst moonshield/disk CHOICES "$CHOICES" || fail "Falha ao preparar a lista de discos."
    db_set moonshield/disk "$FIRST_CHOICE" >/dev/null 2>&1 || true
    db_fset moonshield/disk seen false >/dev/null 2>&1 || true

    input_rc=0
    db_input critical moonshield/disk >/dev/null 2>&1 || input_rc=$?
    [ "$input_rc" -eq 0 ] || [ "$input_rc" -eq 30 ] || fail "Falha ao abrir a seleção de disco (Debconf rc=$input_rc)."
    db_go >/dev/null 2>&1 || continue
    db_get moonshield/disk || fail "Falha ao obter o disco selecionado."
    selected_label="$RET"
    selected="${selected_label%% | *}"

    valid_disk "$selected" || {
        show_error "O disco escolhido não está mais disponível. Selecione outro disco."
        continue
    }

    model="$(model_for "$selected")"
    size="$(size_for "$selected")"
    db_subst moonshield/confirm SELECTED "$selected" || true
    db_subst moonshield/confirm MODEL "$model" || true
    db_subst moonshield/confirm SIZE "$size" || true
    db_set moonshield/confirm false >/dev/null 2>&1 || true
    db_fset moonshield/confirm seen false >/dev/null 2>&1 || true

    input_rc=0
    db_input critical moonshield/confirm >/dev/null 2>&1 || input_rc=$?
    [ "$input_rc" -eq 0 ] || [ "$input_rc" -eq 30 ] || fail "Falha ao abrir a confirmação do disco (Debconf rc=$input_rc)."
    if ! db_go >/dev/null 2>&1; then
        continue
    fi
    db_get moonshield/confirm || fail "Falha ao obter a confirmação da instalação."

    if [ "$RET" = true ]; then
        apply_selected_disk "$selected"
        exit 0
    fi

    log_msg "Usuário recusou a confirmação para $selected; retornando à seleção."
done
