#!/usr/bin/env bash

preflight() {
  local os_id os_version arch disk_kb mem_kb interfaces default_route dns_state
  [[ "$(id -u)" == 0 ]] || die "Execute o installer como root (sudo ./deploy/install.sh)."
  [[ -r /etc/os-release ]] || die "Não foi possível identificar o sistema operacional."
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-unknown}"; os_version="${VERSION_ID:-unknown}"
  [[ "$os_id" == debian && "$os_version" == 13* ]] || die "Sistema incompatível: esperado Debian 13; encontrado ${os_id}/${os_version}."
  arch="$(uname -m)"
  [[ "$arch" == x86_64 ]] || die "Arquitetura incompatível: esperado amd64/x86_64; encontrado $arch."
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || die "systemd não está ativo neste sistema."
  require_command df
  require_command ip
  require_command getent
  disk_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
  mem_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
  interfaces="$(ip -o link show | awk -F': ' '$2 != "lo" {n++} END {print n+0}')"
  default_route="$(ip route show default 2>/dev/null | head -n 1 || true)"
  dns_state="indisponível"
  if [[ "$INSTALL_MODE" == online ]] && getent ahosts deb.debian.org >/dev/null 2>&1; then
    dns_state="resolução de deb.debian.org OK"
  elif [[ "$INSTALL_MODE" == online ]]; then
    dns_state="falha/sem DNS"
  else
    dns_state="não exigido em modo offline"
  fi
  info "Preflight: Debian $os_version / $arch / systemd ativo."
  info "Recursos observados: disco livre ${disk_kb:-0} KiB; RAM disponível ${mem_kb:-0} KiB; interfaces não-loopback ${interfaces:-0}."
  if [[ -z "$default_route" ]]; then
    [[ "$INSTALL_MODE" == offline || "$CHECK_ONLY" == 1 ]] && warn "Sem rota default; nenhuma rota foi alterada." || die "Sem rota default para instalação online."
  else
    info "Rota default observada; nenhuma interface será reconfigurada."
  fi
  if [[ "$INSTALL_MODE" == online && "$CHECK_ONLY" == 0 && "$dns_state" == "falha/sem DNS" ]]; then
    die "Preflight online detectou falha DNS; verifique DNS/proxy sem alterar rede automaticamente."
  fi
  [[ "$interfaces" -gt 0 ]] || warn "Nenhuma interface não-loopback detectada."
  [[ "$disk_kb" =~ ^[0-9]+$ && "$mem_kb" =~ ^[0-9]+$ ]] || die "Não foi possível medir disco/RAM."
  [[ "$disk_kb" -gt 0 && "$mem_kb" -gt 0 ]] || die "Disco ou RAM indisponível."
  ok "Preflight concluído; não foram alterados serviços ou interfaces."
}
