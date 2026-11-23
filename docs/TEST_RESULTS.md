# Test results and reproducibility

**Local test observation:** 23 November 2026, Linux/Python standard-library environment.

~~~text
Ran 40 tests in 2.040s
OK
~~~

The tests cover:
- Tamper-evident HMAC/sha256 ledger, negative tampering cases and off-host anchor comparison
- SSH failure bursts, follow-up logins and imported Guardian alerts
- Static expectations for rsyslog TLS configuration
- Guardian bridge/CLI validation

Reproduce with:

~~~bash
python3 -m unittest discover -s tests -v
python3 -m vault hunt --log samples/remote.log \
  --json output/alerts.json --report output/incident_report.md
~~~

**Unverified by these tests:** remote mTLS transport between real hosts, outage recovery under load, throughput, collector hardening, forensic legal admissibility and production APT detection rates. The separate GitHub Actions CI workflow runs the offline suite on pushes and pull requests.
