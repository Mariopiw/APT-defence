#!/usr/bin/env bash
set -euo pipefail
# Invoke on collector with certs pre-copied under ./pki/; inspect before execution.
cd "$(dirname "$0")/.."
[[ -f pki/ca.crt && -f pki/collector.crt && -f pki/collector.key ]] || { echo 'Missing collector certificate inputs' >&2; exit 2; }
sudo apt-get update
sudo apt-get install -y rsyslog rsyslog-gnutls
getent passwd syslog >/dev/null || { echo 'Missing syslog service user'; exit 2; }
getent group syslog >/dev/null || { echo 'Missing syslog service group'; exit 2; }
sudo install -d -o root -g syslog -m 0750 /etc/rsyslog.d/vault-tls
sudo install -o root -g syslog -m 0644 pki/ca.crt /etc/rsyslog.d/vault-tls/ca.crt
sudo install -o root -g syslog -m 0644 pki/collector.crt /etc/rsyslog.d/vault-tls/collector.crt
sudo install -o root -g syslog -m 0640 pki/collector.key /etc/rsyslog.d/vault-tls/collector.key
sudo install -d -o syslog -g adm -m 0750 /var/log/apt-vault
sudo install -o root -g root -m 0644 configs/collector.conf /etc/rsyslog.d/30-apt-vault.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo systemctl --no-pager status rsyslog || true
printf 'Collector configured. Restrict TCP 6514 to sender private IP via firewall.\n'
