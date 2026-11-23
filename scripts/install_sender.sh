#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f pki/ca.crt && -f pki/sender.crt && -f pki/sender.key ]] || { echo 'Missing sender certificate inputs' >&2; exit 2; }
getent ahostsv4 logs.lab >/dev/null || { echo 'Resolve logs.lab to collector private IP first'; exit 2; }
sudo apt-get update
sudo apt-get install -y rsyslog rsyslog-gnutls
getent passwd syslog >/dev/null || { echo 'Missing syslog service user'; exit 2; }
getent group syslog >/dev/null || { echo 'Missing syslog service group'; exit 2; }
sudo install -d -o root -g syslog -m 0750 /etc/rsyslog.d/vault-tls
sudo install -o root -g syslog -m 0644 pki/ca.crt /etc/rsyslog.d/vault-tls/ca.crt
sudo install -o root -g syslog -m 0644 pki/sender.crt /etc/rsyslog.d/vault-tls/sender.crt
sudo install -o root -g syslog -m 0640 pki/sender.key /etc/rsyslog.d/vault-tls/sender.key
sudo install -o root -g root -m 0644 configs/sender.conf /etc/rsyslog.d/30-apt-vault.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog
logger -p local5.notice -t apt-vault-test "APT_VAULT_TEST_$(date +%s)"
printf 'Sender configured. Check /var/log/apt-vault/remote.log ON COLLECTOR.\n'
