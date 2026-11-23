#!/usr/bin/env bash
set -euo pipefail
# Run separately on both hosts, review commands before execution.
echo 'Removing only vault rsyslog configuration and TLS files (no log deletion).'
sudo rm -f /etc/rsyslog.d/30-apt-vault.conf
sudo rm -f /etc/rsyslog.d/vault-tls/ca.crt \
    /etc/rsyslog.d/vault-tls/collector.crt /etc/rsyslog.d/vault-tls/collector.key \
    /etc/rsyslog.d/vault-tls/sender.crt /etc/rsyslog.d/vault-tls/sender.key
sudo rmdir /etc/rsyslog.d/vault-tls 2>/dev/null || true
sudo rsyslogd -N1
sudo systemctl restart rsyslog
printf 'Evidence logs under /var/log/apt-vault were NOT deleted.\n'
