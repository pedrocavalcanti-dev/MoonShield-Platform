# MoonShield local console

The console is a local, read-only status and diagnostics UI. It has no generic
command prompt. Its only actions are a fixed allowlist of MoonShield service
restarts, plus separately confirmed `systemctl reboot` and `systemctl poweroff`.
Network topology remains owned by the MoonShield web application and Safe Apply.

TTY1 is assigned to `moonshield-console.service`; the stock getty unit under
`/usr/lib/systemd/system` is not edited. The installer may mask getty instances
on TTY2-6 only for a final appliance install. Development installs do not apply
that policy. Recovery then requires physical or hypervisor access to the boot
loader/rescue environment or trusted recovery media. This is not absolute
physical security: a person able to alter the boot process or disk can bypass
console restrictions. GRUB credentials, Secure Boot, and firmware controls are
separate security layers.

On a recovery boot with administrative access, unmask getty with
`systemctl unmask getty@tty2.service getty@tty3.service getty@tty4.service getty@tty5.service getty@tty6.service`.
If an `/etc/systemd/system/getty@ttyN.service` override existed before hardening,
restore its matching timestamped copy from `/var/lib/moonshield/recovery/` after
unmasking; then run `systemctl daemon-reload`. Previous files are retained there
with mode 0600 (symlinks are copied as symlinks). Restore the saved
To restore the normal TTY1 login, disable `moonshield-console.service` and enable
`getty@tty1.service`. These steps require trusted local or hypervisor recovery
access.

F12 opens an undocumented maintenance challenge screen. A fresh nonce and a
hash of `/etc/machine-id` are signed offline by authorized support staff. The
appliance stores only the corresponding public key. Missing key means
`NOT PROVISIONED` and never opens a shell. The signer is under `deploy/support`
and is excluded from release staging. Never place a private key in this tree,
release, bundle, or appliance. The support private key must be kept externally
under controlled custody.

From a trusted support workstation, sign the exact displayed challenge with:

```text
python deploy/support/sign-maintenance-challenge.py --private-key /secure/external/moonshield-maintenance-private.pem --challenge "MOONSHIELD-MAINT-V1|<id>|<nonce>"
```

Paste only the resulting Base64 signature into the local console. Each retry
generates a new nonce; obtain and sign the new challenge after a failed attempt.

The final ISO must provision `deploy/console/maintenance_public.pem` before
using `--final-iso`; that public key is not supplied by this repository.
Development mode can omit it and reports a warning. SSH is not part of the
MoonShield appliance image.

No systemd, TTY, or real appliance behavior is validated by Windows static
checks. Validate on a disposable Debian 13 VM, including TTY1 startup, TTY2-6
recovery, F12 signing/verification, invalid-signature rate limiting,
service restart allowlist, and reboot/poweroff confirmations.
