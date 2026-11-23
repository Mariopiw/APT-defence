# Incident response runbook — remote syslog lab

1. **Verify the signal.** Record UTC time, alert ID, host, source, detection rule and whether the original log is available.
2. **Preserve originals.** Do not modify the collector's source log. Make a restricted working copy and record its SHA-256.
3. **Check collection health.** Confirm rsyslog receiver/forwarder status, clock sync, storage, and queue backlog; identify gaps.
4. **Validate evidence integrity.** Verify ledger HMAC against the log, then compare the final digest to a previously stored *off-host trusted anchor*. A locally generated anchor is not independent proof.
5. **Correlate.** Compare the collector timeline with sender, authentication, audit and host artifacts. Source-supplied hostnames and messages are untrusted.
6. **Determine authorization.** A successful login after failures might be legitimate. Escalate only with substantiating evidence.
7. **Contain only with approval.** Isolation, credential rotation and service changes require an authorized human decision and recovery plan.
8. **Report and archive.** Document time zone, handling, limitations, analyst decision, signatures and retention requirements.

This repository is a learning lab, not a certified digital-forensic workflow.
