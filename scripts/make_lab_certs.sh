#!/usr/bin/env bash
# Run ON A TRUSTED ADMIN SYSTEM. Do NOT copy CA private key to sender/collector.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
if [[ -e pki ]]; then
  echo 'Refusing to overwrite pki/; archive/remove it intentionally first.' >&2
  exit 2
fi
mkdir -m 700 pki
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out pki/ca.key >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 30 -key pki/ca.key -out pki/ca.crt \
  -subj '/CN=APT Vault Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
for role in collector sender; do
  if [[ "$role" == collector ]]; then
    name=logs.lab
    usage=serverAuth
  else
    name=mint-sender.lab
    usage=clientAuth
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "pki/$role.key" >/dev/null 2>&1
  openssl req -new -sha256 -key "pki/$role.key" -out "pki/$role.csr" -subj "/CN=$name"
  cat > "pki/$role.ext" <<EOT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usage
subjectAltName=DNS:$name
EOT
  openssl x509 -req -sha256 -days 30 -in "pki/$role.csr" -CA pki/ca.crt \
    -CAkey pki/ca.key -CAcreateserial -out "pki/$role.crt" \
    -extfile "pki/$role.ext" >/dev/null
  rm -f "pki/$role.csr" "pki/$role.ext"
done
openssl verify -CAfile pki/ca.crt -purpose sslserver pki/collector.crt
openssl verify -CAfile pki/ca.crt -purpose sslclient pki/sender.crt
printf '\nCERTIFICATES GENERATED (30 day lab validity).\n'
printf 'COPY TO COLLECTOR: ca.crt, collector.crt, collector.key\n'
printf 'COPY TO SENDER:    ca.crt, sender.crt, sender.key\n'
printf 'KEEP OFF BOTH:    ca.key (offline secret).\n'
