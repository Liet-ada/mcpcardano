// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command load is the compromised server of the integration tests (decision
// 32, R-10): it holds three of the four connections of the wallet's service
// socket and sends, as fast as the wallet answers, requests that keep the
// single lock: payments to a known destination, which the wallet signs until
// its limits stop it, and payments with a hundred outputs to new
// destinations, which it reads whole before refusing them.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func main() {
	socket := flag.String("socket", "/run/mcpcardano-wallet/service.sock", "the wallet's service socket")
	wallet := flag.String("wallet", "", "the wallet to ask signatures of")
	known := flag.String("to", "", "a destination the wallet already paid")
	duration := flag.Duration("for", 10*time.Second, "how long to keep it busy")
	conns := flag.Int("conns", 3, "connections to hold")
	flag.Parse()
	if err := run(*socket, *wallet, *known, *duration, *conns); err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
}

func run(socket, wallet, known string, duration time.Duration, conns int) error {
	to, err := model.ParseAddress(model.Preprod, known)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	hello := ipc.Hello{Software: "load", Network: string(model.Preprod)}
	first, err := ipc.Dial(ctx, socket, hello)
	if err != nil {
		return err
	}
	var list ipc.WalletList
	if err := first.Call(ctx, ipc.MsgListWallets, &ipc.Empty{}, &list); err != nil {
		return err
	}
	first.Close()
	i := slices.IndexFunc(list.Wallets, func(w ipc.Wallet) bool { return w.ID == wallet })
	if i < 0 {
		return fmt.Errorf("no wallet %s", wallet)
	}
	own := list.Wallets[i].Address

	var mu sync.Mutex
	var latencies []time.Duration
	signed, refused := 0, 0
	var wg sync.WaitGroup
	for n := range conns {
		wg.Go(func() {
			c, err := ipc.Dial(ctx, socket, hello)
			if err != nil {
				fmt.Fprintln(os.Stderr, "load:", err)
				return
			}
			defer c.Close()
			for k := 0; ctx.Err() == nil; k++ {
				body, err := payment(own, to.Raw, n*1_000_000+k, k%2 == 1)
				if err != nil {
					fmt.Fprintln(os.Stderr, "load:", err)
					return
				}
				var res ipc.SignDraftResult
				draft, _ := model.NewDraftID(nil)
				start := time.Now()
				err = c.Call(ctx, ipc.MsgSignDraft, &ipc.SignDraft{WalletID: wallet, DraftID: string(draft), Body: body,
					Inputs: []ipc.ResolvedInput{}}, &res)
				took := time.Since(start)
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				latencies = append(latencies, took)
				if err == nil && res.Status == ipc.Signed {
					signed++
				} else {
					refused++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	slices.Sort(latencies)
	if len(latencies) == 0 {
		return fmt.Errorf("no request was answered")
	}
	fmt.Printf("load: %d SignDraft in %v (%d signed, %d refused); median %v, slowest %v\n",
		len(latencies), duration, signed, refused, latencies[len(latencies)/2], latencies[len(latencies)-1])
	return nil
}

var codec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 8, MaxArrayElements: 4096, MaxMapPairs: 16, AllowTags: true})
	if err != nil {
		panic(err)
	}
	return c
}()

// payment is a transaction body from the wallet: to the known destination,
// or to a hundred new ones when wide. k makes each body unique.
func payment(own, to []byte, k int, wide bool) ([]byte, error) {
	input := bytes.Repeat([]byte{0xee}, 32)
	outputs := []any{[]any{to, uint64(1_000_000)}}
	if wide {
		outputs = nil
		for i := range 100 {
			dest := append([]byte{0x60}, bytes.Repeat([]byte{byte(i)}, 28)...)
			dest[1], dest[2] = byte(k>>8), byte(k)
			outputs = append(outputs, []any{dest, uint64(1_000_000)})
		}
	}
	outputs = append(outputs, []any{own, uint64(50_000_000)})
	ttl := model.Preprod.Clock().Slot(time.Now()) + 600
	return codec.Marshal(map[uint64]any{
		0: cborx.Tag{Number: 258, Content: []any{[]any{input, uint64(k)}}},
		1: outputs,
		2: uint64(200_000 + k%1000),
		3: ttl,
	})
}
