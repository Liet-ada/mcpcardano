# Installing on Linux

`mcpcardano install` installs mcpcardano, and `mcpcardano doctor` checks it (decision 134). Run install with sudo from your own account, in the directory that holds the three binaries:

```
sudo ./mcpcardano install
```

It asks for the password of the wallet's key store twice, without echo. Then log in again, or run `newgrp mcpcardano`, so that your session is in the group mcpcardano, and:

```
mcpcardano unlock
mcpcardano doctor
```

`test/integration/run.sh` does the same in the CI, with a fake data source, and then breaks, one by one, what doctor must find.

## What install does

The wallet and the server run as services of systemd, each with its own user. Their sockets live in their own runtime directories, `0750` with the group `mcpcardano`:

| Socket | Path | Who reaches it |
| --- | --- | --- |
| The wallet's service socket | `/run/mcpcardano-wallet/service.sock` | The server's user |
| The wallet's admin socket | `/run/mcpcardano-wallet/admin.sock` | The person, through `mcpcardano` |
| The server's MCP socket | `/run/mcpcardano-server/mcp.sock` | The person's MCP client, through `mcpcardano mcp` |

The sockets are `0660`. The wallet also checks the user the kernel certifies at the other end of each socket. Nobody but each service can create files in its runtime directory, so nobody can leave a socket that impersonates it.

Before it changes anything, install checks that it runs as root under systemd, that the kernel says the clock is synchronized (the wallet takes the time from it, section 9.3; there is no way to skip this), and that the three binaries are next to it. Then, in order:

1. It copies `mcpcardano`, `mcpcardano-server` and `mcpcardano-wallet` to `/usr/local/bin`, root's and `0755`. The wallet must have been built with `purego` (section 1.1):

   ```
   go build -trimpath -o bin/ ./cmd/mcpcardano ./cmd/mcpcardano-server
   go build -trimpath -tags purego -o bin/ ./cmd/mcpcardano-wallet
   ```

2. It creates the users and the group with `systemd-sysusers` and [sysusers.conf](sysusers.conf), which it puts in `/etc/sysusers.d/mcpcardano.conf`, and adds whoever ran sudo to the group (`-user` names someone else).
3. It installs [mcpcardano-wallet.service](mcpcardano-wallet.service) and [mcpcardano-server.service](mcpcardano-server.service) in `/etc/systemd/system`. The CLI carries these files, so the units it installs are the ones in this directory.
4. It writes `/etc/mcpcardano-wallet/config.json` and `/etc/mcpcardano-server/config.json`, owned by `root:mcpcardano` with mode `0640`, in directories with mode `0750`, and checks them with each binary's `-check`. The network is preprod unless `-network preview`, and the data source is Koios at its public URL unless `-datasource-url` names another. Mainnet stays disabled:

   ```json
   {"network": "preprod", "data_dir": "/var/lib/mcpcardano-wallet",
    "service_socket": "/run/mcpcardano-wallet/service.sock", "admin_socket": "/run/mcpcardano-wallet/admin.sock",
    "service_uid": <id -u mcpcardano-server>, "admin_uid": <your id -u>}
   ```

   ```json
   {"network": "preprod", "data_dir": "/var/lib/mcpcardano-server", "socket": "/run/mcpcardano-server/mcp.sock",
    "wallet_socket": "/run/mcpcardano-wallet/service.sock", "datasource": {"kind": "koios"}, "wallets": []}
   ```

5. It creates the key store with your password, running `mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json init` as the wallet's user, in `/var/lib/mcpcardano-wallet` (`0700`). With Blockfrost among the data sources, it asks for its project id without echo and writes it to `/var/lib/mcpcardano-server/secrets/blockfrost`, the server's alone (below).
6. With `-unlock machine`, it seals the key of the machine with the TPM2 (below).
7. It enables and starts the wallet, and then the server.

It never unlocks the wallet: the admin socket admits only you, and your session is not in the new group until you log in again. It ends by showing the limits of the template that the wallets the agent creates start with, and how to change them with `mcpcardano policy show -template` and `policy set -template`.

`journalctl -u mcpcardano-wallet -u mcpcardano-server` shows what the services log. The wallet refuses to start if it can reach the network, which `PrivateNetwork=yes` prevents.

### Data sources

The server reads the chain from Koios or Blockfrost, or from a list of them in order of preference (decision 136). Each call goes to the first source that answers; one that is down, or answers something invalid, is set aside for a minute and the call goes on to the next. A signed transaction is sent through one source only, never two: if the answer is unclear, the agent's retry asks the chain first.

`-datasource blockfrost,koios` makes Blockfrost the first and Koios its relay; `-datasource blockfrost` uses Blockfrost alone. Blockfrost needs the project id of a project for the same network, from blockfrost.io, which install asks for. In `config.json` the list reads:

```json
"datasource": [{"kind": "blockfrost"}, {"kind": "koios"}]
```

The key is never in `config.json`. The server reads it from a credential of systemd named after `secret` (`blockfrost` by default), if the unit has one, or else from `/var/lib/mcpcardano-server/secrets/<secret>`, which must be the server's with mode `0600`. To add Blockfrost to an installation, put the key there and edit the list:

```sh
sudo install -d -o mcpcardano-server -g mcpcardano -m 0700 /var/lib/mcpcardano-server/secrets
read -rs key  # paste the key; it is not shown
printf '%s\n' "$key" | sudo install -o mcpcardano-server -g mcpcardano -m 0600 /dev/stdin /var/lib/mcpcardano-server/secrets/blockfrost; unset key
sudo systemctl restart mcpcardano-server
```

Blockfrost does not look tokens up by their fingerprint: with it alone, `get_asset_info` asks the agent for the `asset_id`.

Each source has a `name`, its kind unless you give another, as for two Koios: `{"kind": "koios", "name": "my-koios", "url": "http://127.0.0.1:8053/api/v1"}`. The agent sees the names in `get_network_status` and may choose, with `set_datasources`, which of your sources its session reads and in what order (decision 137). It cannot add a source or a URL, its choice ends with the session, and the server's own work, such as following sent transactions, keeps your order. To keep the agent away from a source, leave it out of the list.

### Installing again

Run install again, from the directory of a new version or with the installed CLI, to update: it stops the server and then the wallet, replaces the three binaries and the units, and starts the wallet and then the server (section 10.6). It keeps both `config.json` and the key store, and never rewrites a `master.key`; to change the network or the data source, edit the `config.json`. The wallet starts again locked, unless it is bound to the machine.

### Security keys

The rule `60-fido-id.rules` of systemd marks the FIDO2 security keys, and gives them to whoever has a session at the machine. install warns if it is missing. Over SSH there is no such session, so the CLI cannot reach your key: `-fido-owner` adds `/etc/udev/rules.d/70-mcpcardano-fido.rules`, which gives the keys to you alone. Not to the group mcpcardano: both services are in it. The units also run with `PrivateDevices=yes`.

## The unlock bound to the machine (optional, TPM2)

On a machine with a TPM2, the wallet can start unlocked, without your password (decision 132). A key of the machine, 32 random bytes that nobody sees, is sealed by systemd with the TPM2 and the host's key, and wraps the wallet's data key in `master.key` next to the wrapping by your password. A copy of the wallet's directory, or its disk in another machine, still opens only with the password, and the password always opens. Without a TPM2, skip this: the host's key alone lives on the same disk and adds nothing.

```
sudo ./mcpcardano install -unlock machine
mcpcardano unlock   # once: binds the key store to the key of the machine
```

It needs systemd 254 or later, for `ImportCredential=` in the wallet's unit, and `/dev/tpmrm0`. install writes the credential to `/etc/credstore.encrypted/mcpcardano-wallet.unlock` with `systemd-creds encrypt --with-key=tpm2+host`, passing the key on its standard input. systemd hands the key to the wallet if the credential exists, and skips it if it is missing or does not decrypt, for instance after the TPM2 is cleared. The wallet then starts locked, as without it.

To undo it, run `sudo mcpcardano install -unlock password` and unlock with your password: an unlock without the key of the machine removes its wrapping from `master.key`.

## Uninstalling

```
sudo mcpcardano uninstall
```

It stops and removes the services, the binaries, the users, the group and the key of the machine. It keeps `/etc/mcpcardano-*` and `/var/lib/mcpcardano-*`, given to root with mode `0700`, so that a new user who gets the same uid does not inherit them. Without the key of the machine, a kept key store opens only with its password; install uses it again. `-delete-data` deletes them too, after you type `delete the wallets`: the funds of a wallet whose recovery phrase is not written down are then lost.

## doctor

`mcpcardano doctor` runs as you, needs no sudo and changes nothing. It checks the users and the group, and the owners and modes of the files of the installation: a binary you can write fails, because a program with your user could change it. It also checks:

- that the units run and have the hardening of the files in this directory, as `systemctl show` reports it, drop-ins included;
- that the wallet has no network, from `/proc/<pid>/net/dev` of its process, and that its `config.json` has no `development`;
- that the clock is synchronized and agrees with the tip of the chain;
- that the CLI, the wallet and the server are the same version;
- that the server reaches its data source, and warns about any other source of the list that does not answer;
- the security keys registered, against the ones you can open;
- the hash chains of the wallet's audit log and spending record.

The server checks its own chain when it starts, and does not start if it is broken. doctor exits with 0 if nothing failed, and with 1 otherwise.
