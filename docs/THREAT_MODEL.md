# Threat model — APT Evidence Vault

## Security objective
Detect selected Linux SSH signals and make later alteration of collected, sealed evidence detectable relative to a trusted, separately preserved anchor.

## Assets
- Collector log, ledger and external anchor
- Sender and collector TLS private keys and trusted CA
- HMAC signing key
- Case reports and analyst review notes

## Trust boundaries
1. **Sender:** source event text, hostname, timestamps, and application tags are untrusted. Root compromise can forge and suppress logs.
2. **Transport:** rsyslog mutual TLS authenticates certificate names and encrypts the channel, but does not verify that messages are true.
3. **Collector:** use separate administrators, network restrictions, storage encryption, monitoring, backups and predictable retention.
4. **Integrity:** HMAC ledger detects changes only against a previously trusted value. If attacker controls HMAC key and local ledger, a new ledger can be constructed; an off-host trusted anchor raises the bar.

## Covered threats
- Network interception of authenticated TCP/6514 transport (subject to proper key/CA management)
- Opportunistic tampering with sealed evidence
- SSH brute-force patterns and suspicious success sequences
- Selected forwarded alerts from Guardian

## Not covered
Kernel or firmware compromise, event suppression before forwarding, compromised private CA, compromised collector, forged client-generated events, legal-grade chain-of-custody, disk exhaustion, absolute delivery guarantees, WORM storage, or automated remediation.

## Privacy
Log data can contain personal identifiers, IP addresses and user activity. Collect minimally, retain appropriately, restrict access and never commit actual logs to GitHub.

## Security posture
Defensive, read-only analysis; no exploitation, malicious code or autonomous blocking.
