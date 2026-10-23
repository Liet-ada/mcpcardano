// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package deploy holds what mcpcardano install writes on Linux: the units of
// systemd, the users of systemd-sysusers and where everything goes (sections
// 7.1 and 10.3; decision 134). The files next to this one are the only copy:
// the CLI carries them, and mcpcardano doctor compares the running units
// with them.
package deploy

import _ "embed"

// The units and the users, as in this directory.
var (
	//go:embed mcpcardano-wallet.service
	WalletUnit string
	//go:embed mcpcardano-server.service
	ServerUnit string
	//go:embed sysusers.conf
	SysUsers string
)

// The users of the two services and the group of their sockets and their
// configuration, which the person joins.
const (
	WalletUser = "mcpcardano-wallet"
	ServerUser = "mcpcardano-server"
	Group      = "mcpcardano"
)

// The names of the units.
const (
	WalletService = "mcpcardano-wallet.service"
	ServerService = "mcpcardano-server.service"
)

// Where install puts things.
const (
	BinDir       = "/usr/local/bin"
	UnitDir      = "/etc/systemd/system"
	SysUsersPath = "/etc/sysusers.d/mcpcardano.conf"

	WalletConfigDir = "/etc/mcpcardano-wallet"
	ServerConfigDir = "/etc/mcpcardano-server"
	WalletConfig    = WalletConfigDir + "/config.json"
	ServerConfig    = ServerConfigDir + "/config.json"

	WalletData = "/var/lib/mcpcardano-wallet"
	ServerData = "/var/lib/mcpcardano-server"
	MasterKey  = WalletData + "/keystore/master.key"

	WalletRun     = "/run/mcpcardano-wallet"
	ServerRun     = "/run/mcpcardano-server"
	ServiceSocket = WalletRun + "/service.sock"
	AdminSocket   = WalletRun + "/admin.sock"
	MCPSocket     = ServerRun + "/mcp.sock"

	// Credential is the key of the machine, sealed with the TPM2, that the
	// wallet's unit imports (decision 132).
	Credential = "/etc/credstore.encrypted/mcpcardano-wallet.unlock"
	// FIDORule gives the person's security keys to the person alone, also
	// over SSH, where the rule of systemd for a local session does not reach.
	FIDORule = "/etc/udev/rules.d/70-mcpcardano-fido.rules"
)

// Binaries are the three binaries, which install copies together: the
// server and the wallet share the version of the protocol (section 10.6).
var Binaries = []string{"mcpcardano", "mcpcardano-server", "mcpcardano-wallet"}

// Units are the two units, the wallet's first: it starts before the server
// and stops after it.
var Units = []string{WalletService, ServerService}

// Unit returns the text of a unit by its name, or "" if it is none of the
// two.
func Unit(name string) string {
	switch name {
	case WalletService:
		return WalletUnit
	case ServerService:
		return ServerUnit
	}
	return ""
}
