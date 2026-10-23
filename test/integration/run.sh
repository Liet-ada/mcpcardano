#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Liet-ada
#
# The integration of section 11.1 on Linux. It installs mcpcardano as
# deploy/README.md describes, with systemd and a user for each service and a
# fake Koios as the data source, and runs test/integration as the person, a
# member of the group mcpcardano. It needs sudo and changes the machine: the
# CI runs it on a throwaway one.
set -euo pipefail
cd "$(dirname "$0")/../.."

work=$(mktemp -d)
koios=
tpm=
finish() {
	status=$?
	if [ "$status" -ne 0 ]; then
		sudo journalctl -u mcpcardano-wallet -u mcpcardano-server --no-pager -o short-precise | tail -n 200 || true
	fi
	if [ -n "$koios" ]; then kill "$koios" || true; fi
	if [ -n "$tpm" ]; then sudo pkill -f "swtpm chardev" || true; sudo rm -rf "$tpm"; fi
	rm -rf "$work"
	exit "$status"
}
trap finish EXIT

echo "== build"
go build -trimpath -o "$work/" ./cmd/mcpcardano ./cmd/mcpcardano-server ./test/integration/koios
go build -trimpath -o "$work/mcpcardano-it-load" ./test/integration/load
go build -trimpath -tags purego -o "$work/" ./cmd/mcpcardano-wallet
sudo install -m 0755 "$work/mcpcardano" "$work/mcpcardano-server" "$work/mcpcardano-wallet" "$work/mcpcardano-it-load" /usr/local/bin/

echo "== users, group and units"
sudo systemd-sysusers "$PWD/deploy/sysusers.conf"
sudo usermod -aG mcpcardano "$(id -un)"
sudo install -m 0644 deploy/mcpcardano-wallet.service deploy/mcpcardano-server.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "== configuration"
cat > "$work/wallet.json" <<EOF
{
  "network": "preprod",
  "data_dir": "/var/lib/mcpcardano-wallet",
  "service_socket": "/run/mcpcardano-wallet/service.sock",
  "admin_socket": "/run/mcpcardano-wallet/admin.sock",
  "service_uid": $(id -u mcpcardano-server),
  "admin_uid": $(id -u)
}
EOF
cat > "$work/server.json" <<EOF
{
  "network": "preprod",
  "data_dir": "/var/lib/mcpcardano-server",
  "socket": "/run/mcpcardano-server/mcp.sock",
  "wallet_socket": "/run/mcpcardano-wallet/service.sock",
  "datasource": {"kind": "koios", "url": "http://127.0.0.1:18080"},
  "wallets": []
}
EOF
sudo install -d -m 0750 -o root -g mcpcardano /etc/mcpcardano-wallet /etc/mcpcardano-server
sudo install -m 0640 -o root -g mcpcardano "$work/wallet.json" /etc/mcpcardano-wallet/config.json
sudo install -m 0640 -o root -g mcpcardano "$work/server.json" /etc/mcpcardano-server/config.json

echo "== key store"
head -c 24 /dev/urandom | base64 > "$work/password"
sudo install -d -m 0700 -o mcpcardano-wallet -g mcpcardano /var/lib/mcpcardano-wallet
sudo -u mcpcardano-wallet /usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json init < "$work/password"

echo "== services"
"$work/koios" -listen 127.0.0.1:18080 &
koios=$!
sudo systemctl start mcpcardano-wallet mcpcardano-server
for _ in $(seq 50); do
	if sudo test -S /run/mcpcardano-server/mcp.sock; then break; fi
	sleep 0.2
done
sudo ls -la /run/mcpcardano-wallet /run/mcpcardano-server

echo "== tests, as the person"
sg mcpcardano -c "MCPCARDANO_IT_PASSWORD=$work/password $(command -v go) test -tags integration -count=1 -v ./test/integration/"

echo "== the unlock bound to the machine, with a simulated TPM2 (decision 132)"
sudo apt-get install -y -qq swtpm swtpm-tools > /dev/null
sudo modprobe tpm_vtpm_proxy
tpm=$(sudo mktemp -d)
sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir="$tpm" --flags startup-clear --daemon
for _ in $(seq 50); do
	if [ -e /dev/tpmrm0 ]; then break; fi
	sleep 0.2
done
ls -la /dev/tpm*
sudo systemd-creds has-tpm2 || true
sudo install -d -m 0700 /etc/credstore.encrypted
head -c 32 /dev/urandom | sudo systemd-creds encrypt --with-key=tpm2+host --name=unlock - /etc/credstore.encrypted/mcpcardano-wallet.unlock
sudo install -D -m 0644 deploy/mcpcardano-wallet-unlock.conf /etc/systemd/system/mcpcardano-wallet.service.d/unlock.conf
sudo systemctl daemon-reload
sg mcpcardano -c "MCPCARDANO_IT_PASSWORD=$work/password MCPCARDANO_IT_TPM=1 $(command -v go) test -tags integration -count=1 -v -run TestUnlockByMachine ./test/integration/"

echo "== the credential with another TPM2"
sudo pkill -f "swtpm chardev"
for _ in $(seq 50); do
	if [ ! -e /dev/tpmrm0 ]; then break; fi
	sleep 0.2
done
sudo rm -rf "$tpm"
tpm=$(sudo mktemp -d)
sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir="$tpm" --flags startup-clear --daemon
for _ in $(seq 50); do
	if [ -e /dev/tpmrm0 ]; then break; fi
	sleep 0.2
done
sudo systemctl reset-failed mcpcardano-wallet
if sudo systemctl restart mcpcardano-wallet; then echo "the wallet started"; else echo "the wallet did not start"; fi
sudo systemctl status mcpcardano-wallet --no-pager | head -n 20 || true
sudo journalctl -u mcpcardano-wallet --no-pager -n 20 || true

echo "== observation: ImportCredential, with the same TPM2 and with another"
sudo rm -f /etc/systemd/system/mcpcardano-wallet.service.d/unlock.conf
head -c 32 /dev/urandom | sudo systemd-creds encrypt --with-key=tpm2+host --name=mcpcardano-wallet.unlock - /etc/credstore.encrypted/mcpcardano-wallet.unlock
printf '[Service]\nImportCredential=mcpcardano-wallet.unlock\n' | sudo tee /etc/systemd/system/mcpcardano-wallet.service.d/import.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed mcpcardano-wallet
if sudo systemctl restart mcpcardano-wallet; then echo "import, same TPM2: started"; else echo "import, same TPM2: did not start"; fi
sleep 1
sudo ls -la /run/credentials/mcpcardano-wallet.service/ || true
sudo pkill -f "swtpm chardev"
for _ in $(seq 50); do
	if [ ! -e /dev/tpmrm0 ]; then break; fi
	sleep 0.2
done
sudo rm -rf "$tpm"
tpm=$(sudo mktemp -d)
sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir="$tpm" --flags startup-clear --daemon
for _ in $(seq 50); do
	if [ -e /dev/tpmrm0 ]; then break; fi
	sleep 0.2
done
sudo systemctl reset-failed mcpcardano-wallet
if sudo systemctl restart mcpcardano-wallet; then echo "import, other TPM2: started"; else echo "import, other TPM2: did not start"; fi
sleep 1
sudo systemctl status mcpcardano-wallet --no-pager | head -n 12 || true
sudo ls -la /run/credentials/mcpcardano-wallet.service/ || true
sudo journalctl -u mcpcardano-wallet --no-pager -n 8 || true
