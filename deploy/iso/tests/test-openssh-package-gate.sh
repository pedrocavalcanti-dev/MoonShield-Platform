#!/usr/bin/env bash
set -Eeuo pipefail

contains_openssh_server() {
    awk -F '\t' '$1 == "openssh-server" { found=1 } END { exit !found }' "$1"
}

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT

printf 'libssh2-1t64\t1.11.1-1+deb13u2\tamd64\n' > "$workdir/libssh2.tsv"
if contains_openssh_server "$workdir/libssh2.tsv"; then
    printf '%s\n' 'libssh2-1t64 must not be identified as openssh-server.' >&2
    exit 1
fi

printf 'openssh-server\t1:9.2p1-2+deb13u5\tamd64\n' > "$workdir/openssh-server.tsv"
if ! contains_openssh_server "$workdir/openssh-server.tsv"; then
    printf '%s\n' 'openssh-server must be identified by its exact package name.' >&2
    exit 1
fi

printf '%s\n' 'openssh package gate regression tests passed.'
