# Optional corporate CA

No institution certificate is bundled by default. The operator may supply an
approved PEM X.509 CA at install time with `--ca-cert /path/to/senac-ca.crt`, or
place it in this directory as `optional/senac-ca.crt` before building trusted
release media. The release staging step includes this optional file; Git ignores
`.crt` and `.pem` files here so a CA is not added accidentally.

`CORPORATE_CA_SHA256` in `../manifests/external-artifacts.env` is compared when a
trusted fingerprint is available. A certificate presented by a TLS connection is
never accepted as a trust anchor.
