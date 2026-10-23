# Installing on Linux

Until `mcpcardano install` arrives (milestone H-3), these are the steps by hand. `test/integration/run.sh` runs the same steps in the CI, with a fake data source.

The wallet and the server run as services of systemd, each with its own user. Their sockets live in their own runtime directories, `0750` with the group `mcpcardano`:

| Socket | Path | Who reaches it |
| --- | --- | --- |
| The wallet's service socket | `/run/mcpcardano-wallet/service.sock` | The server's user |
| The wallet's admin socket | `/run/mcpcardano-wallet/admin.sock` | The person, through `mcpcardano` |
| The server's MCP socket | `/run/mcpcardano-server/mcp.sock` | The person's MCP client, through `mcpcardano mcp` |

The sockets are `0660`. The wallet also checks the user the kernel certifies at the other end of each socket. Nobody but each service can create files in its runtime directory, so nobody can leave a socket that impersonates it.

1. Build and install the binaries. The wallet is built with `purego` (section 1.1):

   ```
   go build -trimpath -o bin/ ./cmd/mcpcardano ./cmd/mcpcardano-server
   go build -trimpath -tags purego -o bin/ ./cmd/mcpcardano-wallet
   sudo install -m 0755 bin/mcpcardano bin/mcpcardano-server bin/mcpcardano-wallet /usr/local/bin/
   ```

2. Create the users and the group, join the group, and install the units:

   ```
   sudo systemd-sysusers deploy/sysusers.conf
   sudo usermod -aG mcpcardano "$USER"      # takes effect at the next login
   sudo install -m 0644 deploy/*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Write `/etc/mcpcardano-wallet/config.json` and `/etc/mcpcardano-server/config.json`, owned by `root:mcpcardano` with mode `0640`, in directories with mode `0750`:

   ```json
   {"network": "preprod", "data_dir": "/var/lib/mcpcardano-wallet",
    "service_socket": "/run/mcpcardano-wallet/service.sock", "admin_socket": "/run/mcpcardano-wallet/admin.sock",
    "service_uid": <id -u mcpcardano-server>, "admin_uid": <your id -u>}
   ```

   ```json
   {"network": "preprod", "data_dir": "/var/lib/mcpcardano-server", "socket": "/run/mcpcardano-server/mcp.sock",
    "wallet_socket": "/run/mcpcardano-wallet/service.sock", "datasource": {"kind": "koios"}, "wallets": []}
   ```

4. Create the wallet's key store with your password, typed on the standard input:

   ```
   sudo install -d -m 0700 -o mcpcardano-wallet -g mcpcardano /var/lib/mcpcardano-wallet
   sudo -u mcpcardano-wallet /usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json init
   ```

5. Start the services, and unlock the wallet after each start of it:

   ```
   sudo systemctl enable --now mcpcardano-wallet mcpcardano-server
   mcpcardano unlock
   ```

`journalctl -u mcpcardano-wallet -u mcpcardano-server` shows what they log. The wallet refuses to start if it can reach the network, which `PrivateNetwork=yes` prevents.

## The unlock bound to the machine (optional, TPM2)

On a machine with a TPM2, the wallet can start unlocked, without your password (decision 132). A key of the machine, 32 random bytes that nobody sees, is sealed by systemd with the TPM2 and the host's key, and wraps the wallet's data key in `master.key` next to the wrapping by your password. A copy of the wallet's directory, or its disk in another machine, still opens only with the password, and the password always opens. Without a TPM2, skip this: the host's key alone lives on the same disk and adds nothing.

1. Check that there is a TPM2, and seal the key of the machine with it:

   ```
   systemd-analyze has-tpm2        # systemd-creds has-tpm2 before systemd 257
   sudo install -d -m 0700 /etc/credstore.encrypted
   head -c 32 /dev/urandom | sudo systemd-creds encrypt --with-key=tpm2+host --name=unlock - /etc/credstore.encrypted/mcpcardano-wallet.unlock
   ```

2. Hand it to the wallet, and restart it:

   ```
   sudo install -D -m 0644 deploy/mcpcardano-wallet-unlock.conf /etc/systemd/system/mcpcardano-wallet.service.d/unlock.conf
   sudo systemctl daemon-reload
   sudo systemctl restart mcpcardano-wallet
   ```

3. Unlock once with your password: that binds the key store to the key of the machine. From the next start on, the wallet starts unlocked.

   ```
   mcpcardano unlock
   ```

To undo it, remove `unlock.conf` and the credential, reload systemd, restart the wallet and unlock it with your password: an unlock without the key of the machine removes its wrapping from `master.key`.
