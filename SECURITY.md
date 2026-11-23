# Security policy and safe use

This repository is a **defensive training lab**. Use only on systems you own or are authorized to administer.

- **Do not open port 6514 to the public internet.** Limit it to a known sender on a private network or VPN.
- **Do not commit secrets:** local CA/private keys, HMAC keys, TLS identities, real case logs, API credentials or .env files.
- **Treat logs as untrusted.** A compromised sender can forge records even over authenticated TLS.
- **Preserve evidence.** Analyze copies. Keep off-host, historically trusted integrity anchors for meaningful tamper checks.
- **Review scripts before sudo.** The install scripts configure rsyslog; confirm certificate paths, network routing and SSH/firewall access first.
- **No claims of production certification.** This is not immutable storage, forensic chain of custody or an APT prevention guarantee.
- **No autonomous response.** Investigation and remediation remain human decisions.

If you discover a security weakness, use the repository's private GitHub communication channel with the maintainer instead of posting sensitive details or keys in a public issue. A public disclosure timeline has not been defined.
