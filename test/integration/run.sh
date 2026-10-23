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
# startTPM starts a TPM2 of its own, with a fresh state, as /dev/tpm0.
startTPM() {
	if [ -n "$tpm" ]; then
		sudo pkill -f "swtpm chardev"
		for _ in $(seq 50); do
			if [ ! -e /dev/tpmrm0 ]; then break; fi
			sleep 0.2
		done
		sudo rm -rf "$tpm"
	fi
	tpm=$(sudo mktemp -d)
	sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir="$tpm" --flags startup-clear --daemon
	for _ in $(seq 50); do
		if [ -e /dev/tpmrm0 ]; then break; fi
		sleep 0.2
	done
}
sudo apt-get install -y -qq swtpm swtpm-tools > /dev/null
sudo modprobe tpm_vtpm_proxy
startTPM
sudo install -d -m 0700 /etc/credstore.encrypted
head -c 32 /dev/urandom | sudo systemd-creds encrypt --with-key=tpm2+host --name=mcpcardano-wallet.unlock - /etc/credstore.encrypted/mcpcardano-wallet.unlock
sg mcpcardano -c "MCPCARDANO_IT_PASSWORD=$work/password MCPCARDANO_IT_TPM=bind $(command -v go) test -tags integration -count=1 -v -run TestUnlockByMachine ./test/integration/"

echo "== the same credential with another TPM2"
startTPM
sg mcpcardano -c "MCPCARDANO_IT_PASSWORD=$work/password MCPCARDANO_IT_TPM=other $(command -v go) test -tags integration -count=1 -v -run TestUnlockByMachine ./test/integration/"
