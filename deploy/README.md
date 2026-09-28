# MoonShield Appliance deployment

This tree prepares an installed Debian 13 amd64 appliance. It does not create an ISO.

## Install

Run `sudo bash ./deploy/install.sh` from a trusted, staged release tree. For a prepared
offline bundle, use `sudo bash ./deploy/install.sh --offline /path/to/bundle`.
`--repair` re-runs idempotent reconciliation; it does not reset application data,
rotate the Django key/database password, or overwrite an existing release source.
`--check` runs preflight and the installed read-only healthcheck.

The installer requires root, systemd, Debian 13 amd64, available disk/RAM, and an
online default route plus DNS unless operating from an offline bundle. It does not
configure interface roles, addresses, routes, nftables rules, or create a Django
initial user. Network roles and the first user are configured through MoonShield.

## Offline bundle and release tree

On an internet-connected Debian 13 amd64 builder, stage a clean tree with
`bash ./deploy/scripts/build-release-tree.sh`, then prepare its package/wheel/artifact
bundle with `sudo bash ./deploy/scripts/prepare-offline-bundle.sh /path/to/bundle`.
The preparation step downloads packages/wheels and does not install them on the
builder. The bundle is checksummed; this detects corruption but is not a signed
release. Validate it on a clean Debian 13 VM before using it for ISO construction.
`DEBIAN-PACKAGES.tsv` records exact package versions resolved by that builder;
Debian security revisions are intentionally not hardcoded in the source manifest.

The AdGuard Home v0.107.79 Linux amd64 archive is pinned to the official GitHub
release asset URL and SHA-256 in `manifests/external-artifacts.env`. Refresh both
only from the official release page. No `curl -k`, TLS verification bypass,
live-certificate trust, `apt-key`, or unsigned repository is used.

## TLS and existing state

Corporate download trust and appliance HTTPS are separate. A corporate CA is
accepted only from an explicit `--ca-cert` or the documented optional media path,
after X.509 validation (and fingerprint validation when configured). Appliance
TLS is enabled only when the operator supplies a matching certificate/key pair at
`/etc/moonshield/tls/fullchain.pem` and `privkey.pem`; the private key must be
root:root mode 0600. Without it, Nginx serves HTTP and emits a warning.

For a SENAC CA, supply the institution-approved PEM file with
`--ca-cert /media/certificates/senac-ca.crt`, or place it on trusted build media as
`deploy/certificates/optional/senac-ca.crt` before preparing the offline bundle.
The installer never discovers or trusts a certificate from the live connection.

Existing MoonShield source, secrets, database credentials/data, AdGuard data,
NetworkManager profiles, nftables rules, and unrelated Nginx/systemd files are not
reset. Installer-managed Nginx/web files are backed up before replacement. Failed
package/service stages stop with a classified diagnostic; the installer does not
attempt a destructive whole-machine rollback.

## Validation boundary

Windows static checks do not validate NetworkManager, nftables, systemd, Suricata,
AdGuard, PostgreSQL service startup, or real DNS behavior. Final acceptance must
include clean-VM install, reboot/recovery, onboarding, topology application, IDS/DNS
integration, Nginx/TLS, and offline installation on Debian 13 amd64.
