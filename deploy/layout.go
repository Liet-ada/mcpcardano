// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package deploy

import (
	_ "embed"
	"runtime"
)

// The daemons of launchd and the wallet's Seatbelt profile on macOS, as in
// this directory (decision 140).
var (
	//go:embed mcpcardano-wallet.plist
	WalletPlist string
	//go:embed mcpcardano-server.plist
	ServerPlist string
	//go:embed wallet.sb
	WalletProfile string
)

// Where install puts things on macOS: the shape of Linux, with the data in
// /Library/Application Support and the sockets in /usr/local/var/run, which
// macOS does not empty at its start as it does /var/run (decision 140). The
// binaries and the configuration go where they go on Linux.
const (
	MacWalletData = "/Library/Application Support/mcpcardano-wallet"
	MacServerData = "/Library/Application Support/mcpcardano-server"
	MacWalletRun  = "/usr/local/var/run/mcpcardano-wallet"
	MacServerRun  = "/usr/local/var/run/mcpcardano-server"
	LaunchDaemons = "/Library/LaunchDaemons"
	// ProfilePath is the wallet's Seatbelt profile, root's, which the
	// wallet cannot change.
	ProfilePath = WalletConfigDir + "/wallet.sb"
	// LogDir holds the logs of the two daemons: launchd does not take them
	// to the unified log.
	LogDir = "/Library/Logs/mcpcardano"
)

// The labels of the two daemons, and the names of their plists.
const (
	WalletLabel = "mcpcardano-wallet"
	ServerLabel = "mcpcardano-server"
)

// Layout is where mcpcardano lives on one system, for install and doctor.
type Layout struct {
	// MacOS is true for launchd, false for systemd.
	MacOS                  bool
	WalletData, ServerData string
	MasterKey              string
	WalletRun, ServerRun   string
	ServiceSocket          string
	AdminSocket            string
	MCPSocket              string
	// ServiceDir holds the definitions of the two services: the units of
	// systemd or the plists of launchd.
	ServiceDir string
	// Services are the file names of the two definitions, the wallet's
	// first: it starts before the server and stops after it.
	Services []string
}

// Linux is the layout of section 7.1 and decision 134.
var Linux = Layout{
	WalletData: WalletData, ServerData: ServerData, MasterKey: MasterKey,
	WalletRun: WalletRun, ServerRun: ServerRun,
	ServiceSocket: ServiceSocket, AdminSocket: AdminSocket, MCPSocket: MCPSocket,
	ServiceDir: UnitDir, Services: Units,
}

// MacOS is the layout of decision 140.
var MacOS = Layout{
	MacOS:      true,
	WalletData: MacWalletData, ServerData: MacServerData, MasterKey: MacWalletData + "/keystore/master.key",
	WalletRun: MacWalletRun, ServerRun: MacServerRun,
	ServiceSocket: MacWalletRun + "/service.sock", AdminSocket: MacWalletRun + "/admin.sock", MCPSocket: MacServerRun + "/mcp.sock",
	ServiceDir: LaunchDaemons, Services: []string{WalletLabel + ".plist", ServerLabel + ".plist"},
}

// Current is the layout of the system this runs on.
func Current() Layout {
	if runtime.GOOS == "darwin" {
		return MacOS
	}
	return Linux
}

// Service returns the text of a service's definition by its file name, or ""
// if it is none of the two.
func (l Layout) Service(name string) string {
	if !l.MacOS {
		return Unit(name)
	}
	switch name {
	case WalletLabel + ".plist":
		return WalletPlist
	case ServerLabel + ".plist":
		return ServerPlist
	}
	return ""
}
