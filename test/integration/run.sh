#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Liet-ada
#
# The integration of section 11.1 on Linux. It installs mcpcardano with
# mcpcardano install (decision 134), with systemd and a user for each service
# and a fake Koios as the data source, checks it with mcpcardano doctor, and
# runs test/integration as the person, a member of the group mcpcardano. Then,
# one phase at a time, it breaks what doctor must find, binds the wallet to a
# simulated TPM2, and uninstalls. It needs sudo and changes the machine: the
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
	if [ -n "$koios" ]; then
		kill "$koios" || true
		wait "$koios" || true
	fi
	if [ -n "$tpm" ]; then sudo pkill -f "swtpm chardev" || true; sudo rm -rf "$tpm"; fi
	# Cleaning up is not what the job checks: under set -e a failed rm would
	# turn a green run red. It once found the directory not empty; what is
	# left it lists instead.
	if ! rm -rf "$work"; then
		echo "::warning::$work is not removed" >&2
		ls -laR "$work" >&2 || true
	fi
	exit "$status"
}
trap finish EXIT

# tests runs test/integration as the person, in a session of the group, in a
# phase (see phase in integration_test.go).
tests() {
	sg mcpcardano -c "MCPCARDANO_IT_PASSWORD=$work/password MCPCARDANO_IT_WORK=$work MCPCARDANO_IT_PHASE=$1 $(command -v go) test -tags integration -count=1 -v ${2:+-run $2} ./test/integration/"
}

echo "== build"
go build -trimpath -o "$work/bin/" ./cmd/mcpcardano ./cmd/mcpcardano-server
go build -trimpath -tags purego -o "$work/bin/" ./cmd/mcpcardano-wallet
go build -trimpath -o "$work/" ./test/integration/koios
go build -trimpath -o "$work/mcpcardano-it-load" ./test/integration/load
# A server of another version, for doctor to find.
go build -trimpath -ldflags "-X main.version=other" -o "$work/other/" ./cmd/mcpcardano-server
sudo install -m 0755 "$work/mcpcardano-it-load" /usr/local/bin/

echo "== the clock"
timedatectl show -p NTP -p NTPSynchronized || true

echo "== install"
# The runners of GitHub leave /usr/local/bin writable by everyone, where
# anyone could replace the binaries: install refuses that, and doctor too.
sudo chmod 0755 /usr/local/bin
"$work/koios" -listen 127.0.0.1:18080 &
koios=$!
head -c 24 /dev/urandom | base64 > "$work/password"
# install ends once both services answer on their sockets.
sudo "$work/bin/mcpcardano" install -datasource-url http://127.0.0.1:18080 < "$work/password"
sudo ls -la /run/mcpcardano-wallet /run/mcpcardano-server

echo "== doctor"
sg mcpcardano -c "mcpcardano doctor"

echo "== tests, as the person"
tests ""

echo "== doctor finds what is broken"
tests doctor TestDoctor

echo "== an API key, encrypted for the server (decision 138)"
tests apikey TestAPIKey

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
# Installing again updates in place, and seals the key of the machine.
sudo mcpcardano install -unlock machine
tests tpm-bind TestUnlockByMachine

echo "== the same credential with another TPM2"
startTPM
tests tpm-other TestUnlockByMachine

echo "== uninstall, install again over what it kept, and uninstall with the data"
tests uninstall TestUninstall
