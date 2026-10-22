// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package policy

import "github.com/Liet-ada/mcpcardano/internal/model"

const ada = 1_000_000

// DefaultTemplate is the template of the wallets the agent creates on network
// n (section 3.7): mode C with a small budget and open destinations, with
// brakes so that a deceived agent can neither empty the budget at once nor
// spread it over many addresses (decision 28). The values are provisional
// until experiment E6: the budget, the limit per transaction and the new
// destinations come from decision 96, the rest from decision 106.
func DefaultTemplate(n model.Network) model.Template {
	return model.Template{
		Mode: model.ModeC,
		Policy: model.Policy{
			Networks: []model.Network{n},
			Limits: model.Limits{
				PerTx:   20 * ada, // a fifth of the budget
				PerHour: 40 * ada,
				PerDay:  100 * ada,
				Budget:  100 * ada,
				MaxFee:  2 * ada,

				TxPerHour:              10,
				NewDestinationsPerHour: 2,
				NewDestinationsPerDay:  5,
				MaxLiveDrafts:          5,
				MaxTTLSeconds:          7200,
			},
			Destinations: model.Destinations{Any: true},
			UTxO:         model.UTxOPolicy{TargetADAOnly: 3, MinSplit: 5 * ada, DustThreshold: ada, MaxDustSweep: 2},
		},
	}
}
