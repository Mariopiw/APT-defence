# APT-defence
### Secure Remote Logging & Tamper-Evident APT Evidence Vault

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/Mariopiw/APT-defence/actions/workflows/ci.yml/badge.svg)](https://github.com/Mariopiw/APT-defence/actions/workflows/ci.yml)
![Linux](https://img.shields.io/badge/Platform-Linux-333333?logo=linux&logoColor=white)
![Scope](https://img.shields.io/badge/Scope-Defensive%20Lab-188A69)

A reproducible **Linux detection engineering and incident-response laboratory** that forwards selected security logs over mutually authenticated TLS, verifies evidence integrity with SHA-256 and HMAC-SHA256, and performs rule-based threat hunting on SSH activity and forwarded security alerts.

Designed for **Linux Mint XFCE / ThinkPad T460** as the sending host and **Ubuntu Server** as a separately managed log collector. Its offline test suite requires only Python 3.10+ and the standard library.

> **Security scope:** This is an educational proof of concept, **not a certified forensic vault, production SIEM/EDR, or guaranteed APT prevention system**. Suspicious activity produces analyst triage leads, not proof of compromise or attribution.

## Features

- **Remote evidence collection:** rsyslog over TCP/6514 with GnuTLS and X.509 peer-name verification.
- **Selective ingestion:** forwards only auth, authpriv, daemon, and local5 syslog facilities; reduces unnecessary collection.
- **Resilient transport:** bounded rsyslog disk-assisted queue for temporary connectivity interruptions.
- **Tamper-evident snapshots:** per-record SHA-256 hash chain, HMAC-SHA256 signatures, and independently preserved final anchor.
- **Detection engine:** Python correlates repeated failed SSH logins, successful login following failures, and forwarded APT Guardian alerts.
- **Integration:** a minimal bridge publishes alert metadata from the Linux APT Defense lab.
- **Repeatability:** synthetic RFC 5737 TEST-NET IPs, automated unit tests, and GitHub Actions CI.
- **Safety:** no malware execution, active exploitation, automated account blocking, or AI-directed remediation.

## Architecture

~~~mermaid
flowchart LR
  A["Linux Mint sender<br/>auth / authpriv / daemon / local5"] --> B["rsyslog<br/>mTLS client + bounded queue"]
  B -->|"TCP 6514 · private network/VPN"| C["Ubuntu collector<br/>rsyslog mTLS listener"]
  C --> D["remote.log"]
  D --> E["SHA-256 hash chain<br/>HMAC-SHA256 ledger"]
  E --> F["Independent, off-host<br/>trusted anchor"]
  D --> G["Python threat hunting"]
  G --> H["JSON alerts + Markdown report"]
  H --> I["Human analyst review"]
~~~

**Trust boundary:** a compromised sender can forge or suppress events before transmission. Mutual TLS authenticates transport peers; it does **not** establish the truth of a log message. Evidence is meaningfully separated only when the collector and the anchor are independently controlled.

## Quick start — safe offline lab

**Prerequisites:** Linux, Python 3.10+, and the repository. No cloud account, Docker, root permissions, or Ollama is necessary for the offline exercises.

~~~bash
git clone https://github.com/Mariopiw/APT-defence.git
cd APT-defence

# Run regression tests
python3 -m unittest discover -s tests -v

# Detect suspicious events in synthetic sample logs
python3 -m vault hunt \
  --log samples/remote.log \
  --json output/alerts.json \
  --report output/incident_report.md

cat output/incident_report.md
~~~

Expected sample output: **three triage alerts** (SSH brute-force threshold, success after repeated failures, and a forwarded Guardian alert). Actual results depend on the data and rules. Use the test suite as the authoritative regression check.

### Seal and verify a sample log

~~~bash
umask 077
python3 -m vault new-key output/hmac.key

python3 -m vault seal \
  --log samples/remote.log \
  --key output/hmac.key \
  --ledger output/demo-ledger.json \
  --anchor output/demo-anchor.txt

python3 -m vault verify \
  --log samples/remote.log \
  --key output/hmac.key \
  --ledger output/demo-ledger.json \
  --anchor output/demo-anchor.txt
~~~

Copy the **trusted anchor** to separate protected storage immediately after sealing in any real-world workflow. Verification against an anchor stored only on the compromised collector does not prove independent integrity.

**Tampering exercise:** duplicate the sample log, change a byte in the copy, and run verification with the original ledger and anchor. Verification should fail. Never deliberately modify actual incident evidence.

## Two-host mTLS deployment (optional)

Only perform these steps on systems you own or administer. **Read each script before running it** and create backups/snapshots first.

1. **Trusted admin environment:** generate 30-day *lab-only* certificates using <code>bash scripts/make_lab_certs.sh</code>. Keep <code>pki/ca.key</code> offline and **never commit** it.
2. **Collector (separate Ubuntu/Linux host):** transfer <code>ca.crt</code>, <code>collector.crt</code>, <code>collector.key</code>. Allow TCP 6514 **only from the sender's private IP**. Execute <code>bash scripts/install_collector.sh</code> on the collector.
3. **Sender (Linux Mint):** make <code>logs.lab</code> resolve to the collector's private IP. Transfer <code>ca.crt</code>, <code>sender.crt</code>, <code>sender.key</code>. Execute <code>bash scripts/install_sender.sh</code> on the sender.
4. **Verify syntax and transport:** on both hosts run <code>sudo rsyslogd -N1</code>. Send a test log from the sender and check the collector's log.

~~~bash
# On sender
logger -p local5.notice -t apt-vault-test "APT_VAULT_TEST"

# On collector
sudo grep -F "APT_VAULT_TEST" /var/log/apt-vault/remote.log
~~~

**Important operational notes:** never expose this lab listener openly to the Internet; use a private network or VPN. Protect existing SSH access before modifying firewall rules. The bounded sender queue can fill or lose unsent events during outages. A VM hosted on the same compromised laptop does **not** provide independent evidence preservation.

For exact certificate handling, system prerequisites, commands, and rollback, see the [full Polish step-by-step guide](FULL_PROJECT5_KROK_PO_KROKU_PL.md).

## Detection coverage and limitations

| Signal | Detection logic | Interpretation |
| --- | --- | --- |
| SSH password failures | At least 5 failures from a source in 5 minutes | Suspected brute force (MITRE ATT&CK T1110) |
| SSH success after failures | Successful authentication after a failure burst from same source/host | Suspicious sequence; not proof of account compromise |
| Forwarded Guardian alert | Approved alert metadata received through local5 | Additional lead requiring independent verification |

**Out of scope:** prevention of root/kernel/firmware compromise; immutable WORM storage; authenticated truth of application logs; comprehensive auditd forwarding; lossless delivery guarantees; production-grade incident chain of custody; automated response.

## Repository layout

~~~text
vault/                  Python CLI, hash-chain ledger, threat-hunting engine
configs/                rsyslog sender/collector TLS configurations
scripts/                PKI generation, installation, rollback, Guardian bridge
tests/                  Python unittest regression and negative tests
samples/                Synthetic SSH and Guardian example logs
docs/                   Threat model, incident runbook, test evidence
FULL_PROJECT5_KROK_PO_KROKU_PL.md  Full hands-on walkthrough in Polish
PELNY_KOD_ZRODLOWY.md             Consolidated source-code reference
.github/workflows/ci.yml           Automated safety and regression checks
~~~

## Testing and quality gates

~~~bash
python3 -m unittest discover -s tests -v
bash -n scripts/*.sh
python3 -m vault hunt --log samples/remote.log \
  --json output/alerts.json --report output/incident_report.md
~~~

The original local laboratory suite passed **40/40 tests on 23 November 2026**. CI verifies the source after every push; passing unit tests do not imply the multi-host rsyslog transport was tested in production. Review the [test notes](docs/TEST_RESULTS.md).

## Defensive operations and cleanup

- Review logs as **untrusted evidence**. Authenticate the collector independently.
- Keep private keys, raw real-world log files, environment files, HMAC secrets, and case data **out of Git**.
- Preserve original evidence and document changes. Never test tampering against originals.
- To remove the laboratory rsyslog installation, read and run <code>bash scripts/remove_vault.sh</code> **on each host separately**. It preserves collected evidence and does not undo firewall changes.

See [Threat Model](docs/THREAT_MODEL.md), [Incident Runbook](docs/INCIDENT_RUNBOOK.md), and [Security Guidance](SECURITY.md).

## Further improvements

Independent immutable/WORM backups, collector hardening, restricted remote administration, key rotation, monitored queue/delivery loss, explicit time-sync validation, stronger forensic retention controls, and adversarial test datasets.

## License

No open-source license is currently granted. The repository owner can choose and add a license before public redistribution.
