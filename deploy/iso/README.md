# MoonShield ISO Alpha 1

This builds `MoonShield-0.1.0-alpha.1-amd64.iso` from a clean, pinned Debian 13
amd64 netinst image. It does not snapshot a running VM or install MoonShield on
the builder. The Debian Installer remains interactive for disk layout and
identity; the profile selects only the standard system task (no desktop) and
schedules the offline MoonShield installer for the installed system's first boot.

## Builder prerequisites

Run the build on Debian 13 amd64. The builder must already have `bash`,
`xorriso`, `openssl`, `python3`, `dpkg`, `coreutils`, and `util-linux` available.
`xorriso` performs the ISO remaster; its `-boot_image any replay` operation
replays the source ISO's boot configuration after the files are mapped. The
script also verifies the expected Debian BIOS (`isolinux`) and UEFI (GRUB EFI)
layout before writing. It does not install packages or alter builder services,
network, TTY, SSH, or databases. The separate offline-bundle preparation step
uses the existing APT and pip download tools and requires an internet-connected
Debian 13 amd64 host with root access.

## 1. Obtain and authenticate the Debian base

The pinned base is Debian `13.7.0`, amd64 netinst. Its versioned source is:

`https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso`

Do not substitute a `current` or `latest` image. Download the ISO and its
checksum/signature files from that same versioned directory. Verify the Debian
signature using a trusted Debian CD signing keyring, then verify the ISO hash
against the signed `SHA256SUMS` entry:

```bash
BASE_DIR=/var/tmp/moonshield-debian-base
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"
curl -fL --proto '=https' --tlsv1.2 \
  https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso \
  -o debian-13.7.0-amd64-netinst.iso
curl -fL --proto '=https' --tlsv1.2 \
  https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/SHA256SUMS \
  -o SHA256SUMS
curl -fL --proto '=https' --tlsv1.2 \
  https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/SHA256SUMS.sign \
  -o SHA256SUMS.sign
gpgv --keyring /usr/share/keyrings/debian-cd-archive-keyring.gpg SHA256SUMS.sign SHA256SUMS
grep -F '  debian-13.7.0-amd64-netinst.iso' SHA256SUMS | sha256sum --check
```

The repo manifest deliberately keeps
`DEBIAN_ISO_SHA256=REQUIRED_BEFORE_BUILD` until that signature and checksum have
been verified by the release operator. Copy the exact 64-character digest from
the verified `SHA256SUMS` entry into
`deploy/iso/manifests/debian-base.env`. The builder rejects the required marker,
any malformed digest, another filename, or a checksum mismatch; it never
guesses a value or follows a moving URL.

## 2. Provision the public maintenance key

Place only the approved RSA public key at
`deploy/console/maintenance_public.pem` before creating the release tree. It
must be valid PEM and at least 3072 bits. The ISO builder fails with
`MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO` if absent and rejects an invalid or
undersized key. Do not generate, copy, or include the signing private key on the
builder, release tree, or ISO.

## 3. Create release and offline bundle

Use fresh output paths outside the source checkout; these commands preserve an
existing output rather than replacing it:

```bash
sudo bash deploy/scripts/build-release-tree.sh /var/tmp/moonshield-alpha1-release
sudo bash deploy/scripts/prepare-offline-bundle.sh /var/tmp/moonshield-alpha1-offline
```

The release tree excludes development secrets/state, `.git`, logs, SQLite,
tests, and `deploy/support`. The offline bundle contains the packages, Python
wheels, pinned AdGuard artifact, and its own `SHA256SUMS`; the ISO builder
revalidates that bundle before embedding it.

## 4. Build and verify the ISO

After replacing the Debian SHA marker with the operator-verified value, run on
the Debian 13 amd64 builder:

```bash
sudo bash deploy/iso/build-iso.sh \
  /var/tmp/moonshield-debian-base/debian-13.7.0-amd64-netinst.iso \
  /var/tmp/moonshield-alpha1-release \
  /var/tmp/moonshield-alpha1-offline
```

The output is ignored by Git and is written to `build/iso/`:

```text
build/iso/MoonShield-0.1.0-alpha.1-amd64.iso
build/iso/MoonShield-0.1.0-alpha.1-amd64.iso.sha256
```

Verify the finished file with:

```bash
cd build/iso
sha256sum --check MoonShield-0.1.0-alpha.1-amd64.iso.sha256
```

The remaster maps the release to `/moonshield/release`, the offline bundle to
`/moonshield/offline-bundle`, and the preseed/hook to `/moonshield/`. The Debian
text installer and GRUB installer entry are pointed at that preseed. Its
late-command copies both payloads into the installed target and enables a
one-shot first-boot unit. The unit invokes
`deploy/install.sh --offline /var/lib/moonshield-iso-bootstrap/offline-bundle
--final-iso` after the installed system has booted under systemd. Thus the existing installer applies the
TTY1 console, TTY2-6, SSH, and maintenance-key policies; this ISO layer does not
reimplement those policies. No Django account is pre-created; onboarding
remains the existing first-user flow.

`xorriso -boot_image any replay` preserves the base media's BIOS/UEFI boot
metadata, and the builder refuses a base missing the expected BIOS/UEFI files.
This is a static/layout check, not proof that firmware boots the result. Boot
the ISO in a new disposable VM with an empty virtual disk, complete the Debian
Installer prompts, then verify after reboot that TTY1 opens MoonShield Console,
the web onboarding is reachable when networking is configured, and the
offline/final-install policies match expectations. Do not point the ISO
installer at a development appliance or a disk containing data to preserve.
