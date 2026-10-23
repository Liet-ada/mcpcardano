// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package archtest enforces the package boundaries of section 2.4 of the
// specification: the wallet never imports server code, network libraries or
// the MCP SDK, and neither the server nor the CLI contain signing code.
package archtest

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const module = "github.com/Liet-ada/mcpcardano"

// Packages shared by the three binaries (section 2.2).
var common = []string{"model", "policy", "ipc", "audit", "cborx"}

var (
	serverOnly = []string{"server", "mcp", "drafts", "txbuild", "txdecode", "sanitize", "plutus", "chain", "datasource", "venues"}
	walletOnly = []string{"walletd", "txcheck", "keystore", "ledger", "hdkey", "authz"}
	cliOnly    = []string{"cli", "fido", "tui", "signer", "mcpclient", "install", "doctor"}

	// deployPkg holds what install writes, which only the CLI carries.
	deployPkg = module + "/deploy"

	// External modules the wallet must never link (section 2.4).
	walletForbiddenExternal = []string{
		"github.com/blinklabs-io/gouroboros",
		"github.com/blinklabs-io/plutigo",
		"github.com/modelcontextprotocol/go-sdk",
	}
	mcpSDK = "github.com/modelcontextprotocol/go-sdk"
)

type pkg struct {
	ImportPath string
	Standard   bool
	Imports    []string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// deps returns the transitive dependencies of a binary under cmd/, or nil if
// the binary does not exist yet.
func deps(t *testing.T, binary string, tags ...string) []pkg {
	t.Helper()
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "cmd", binary)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	args := []string{"list", "-deps", "-json"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "./cmd/"+binary)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", binary, err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func internal(name string) string { return module + "/internal/" + name }

func hasPrefix(path string, prefixes ...string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func internals(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = internal(n)
	}
	return out
}

func TestWalletDependencies(t *testing.T) {
	forbidden := append(append(internals(serverOnly), internals(cliOnly)...), deployPkg)
	forbidden = append(forbidden, walletForbiddenExternal...)
	for _, p := range deps(t, "mcpcardano-wallet", "purego") {
		if hasPrefix(p.ImportPath, forbidden...) {
			t.Errorf("wallet links forbidden package %s", p.ImportPath)
		}
	}
}

func TestNoSigningCodeOutsideWallet(t *testing.T) {
	for _, bin := range []string{"mcpcardano-server", "mcpcardano"} {
		for _, p := range deps(t, bin) {
			if hasPrefix(p.ImportPath, internals([]string{"keystore", "hdkey", "ledger", "authz"})...) {
				t.Errorf("%s links signing package %s", bin, p.ImportPath)
			}
		}
	}
}

func TestNoUnsafeInWallet(t *testing.T) {
	for _, p := range deps(t, "mcpcardano-wallet", "purego") {
		if p.Standard {
			continue
		}
		for _, imp := range p.Imports {
			if imp == "unsafe" {
				t.Errorf("wallet dependency %s imports unsafe", p.ImportPath)
			}
		}
	}
}

func TestNoMCPSDKInCLI(t *testing.T) {
	for _, p := range deps(t, "mcpcardano") {
		if hasPrefix(p.ImportPath, mcpSDK) {
			t.Errorf("CLI links the MCP SDK through %s", p.ImportPath)
		}
	}
}

// TestExternalDependenciesStayEncapsulated checks rule 4 of section 2.3: each
// large external dependency is imported by one package only, so an upgrade
// touches only that package.
func TestExternalDependenciesStayEncapsulated(t *testing.T) {
	owners := map[string]string{
		"github.com/blinklabs-io/gouroboros": internal("chain"),
		"github.com/blinklabs-io/plutigo":    internal("plutus"),
		mcpSDK:                               internal("mcp"),
		"github.com/go-authn/fido":           internal("fido"),
		"github.com/go-macos/":               internal("fido"),
		"github.com/charmbracelet/":          internal("tui"),
		"charm.land/":                        internal("tui"),
	}
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p struct {
			pkg
			TestImports  []string
			XTestImports []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		imports := append(append(p.Imports, p.TestImports...), p.XTestImports...)
		for _, imp := range imports {
			for dep, owner := range owners {
				if hasPrefix(imp, dep) && !hasPrefix(p.ImportPath, owner) {
					t.Errorf("%s imports %s, which only %s may import", p.ImportPath, imp, owner)
				}
			}
		}
	}
}

// TestCommonPackagesStayCommon checks rule 1 of section 2.3: the shared
// packages import only the standard library, golang.org/x and fxamacker/cbor.
func TestCommonPackagesStayCommon(t *testing.T) {
	root := repoRoot(t)
	for _, name := range common {
		dir := filepath.Join(root, "internal", name)
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		cmd := exec.Command("go", "list", "-json", "./internal/"+name+"/...")
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %s: %v", name, err)
		}
		dec := json.NewDecoder(strings.NewReader(string(out)))
		for dec.More() {
			var p pkg
			if err := dec.Decode(&p); err != nil {
				t.Fatal(err)
			}
			for _, imp := range p.Imports {
				switch {
				case !strings.Contains(strings.SplitN(imp, "/", 2)[0], "."): // standard library
				case hasPrefix(imp, "golang.org/x", "github.com/fxamacker/cbor"):
				case hasPrefix(imp, internals(common)...):
				default:
					t.Errorf("%s imports %s, outside what rule 1 allows", p.ImportPath, imp)
				}
			}
		}
	}
}
