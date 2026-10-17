// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package drafts

import "fmt"

// State is the state of a draft (section 3.4 of the specification).
type State string

const (
	StateDraft           State = "draft"
	StateAuthorizing     State = "authorizing"
	StatePendingApproval State = "pending_approval"
	StateSigned          State = "signed"
	StateSubmitted       State = "submitted"
	StateConfirmed       State = "confirmed"
	StateRolledBack      State = "rolled_back"
	StateCancelled       State = "cancelled"
	StateRejected        State = "rejected"
	StateExpired         State = "expired"
	StateFailed          State = "failed"
)

// States lists every state, in the order of section 3.4.
var States = []State{
	StateDraft, StateAuthorizing, StatePendingApproval, StateSigned, StateSubmitted,
	StateConfirmed, StateRolledBack, StateCancelled, StateRejected, StateExpired, StateFailed,
}

// Event is what moves a draft from one state to another.
type Event string

const (
	EventAuthorize   Event = "authorize"    // authorize_draft
	EventAskApproval Event = "ask_approval" // the person must approve or sign; in mode A, always
	EventSign        Event = "sign"         // a signature that matches the draft
	EventReject      Event = "reject"       // the policy or the person says no
	EventCancel      Event = "cancel"       // cancel_draft
	EventSubmit      Event = "submit"       // the server sent it to the network
	EventConfirm     Event = "confirm"      // it reached the configured depth, or went deeper
	EventFail        Event = "fail"         // the node rejected it
	EventRollBack    Event = "roll_back"    // a reorganization took it out of the chain
	EventReenter     Event = "reenter"      // it is back in the chain or the mempool
	EventExpire      Event = "expire"       // the draft or its TTL ran out
)

// Events lists every event.
var Events = []Event{
	EventAuthorize, EventAskApproval, EventSign, EventReject, EventCancel, EventSubmit,
	EventConfirm, EventFail, EventRollBack, EventReenter, EventExpire,
}

// transitions is the state machine of section 3.4: from each state, the
// events it accepts and where they lead. Anything not listed is refused.
// Before the transaction can reach the chain, any state may end in a final
// state; once it is signed, only the network decides.
var transitions = map[State]map[Event]State{
	StateDraft: {
		EventAuthorize: StateAuthorizing,
		EventCancel:    StateCancelled,
		EventExpire:    StateExpired,
	},
	StateAuthorizing: {
		EventAskApproval: StatePendingApproval,
		EventSign:        StateSigned,
		EventReject:      StateRejected,
		EventCancel:      StateCancelled,
		EventExpire:      StateExpired,
	},
	StatePendingApproval: {
		EventSign:   StateSigned,
		EventReject: StateRejected,
		EventCancel: StateCancelled,
		EventExpire: StateExpired,
	},
	StateSigned: {
		EventSubmit: StateSubmitted,
		EventFail:   StateFailed,
		EventExpire: StateExpired,
	},
	StateSubmitted: {
		EventConfirm: StateConfirmed,
		EventFail:    StateFailed,
		EventExpire:  StateExpired,
	},
	StateConfirmed: {
		EventConfirm:  StateConfirmed,
		EventRollBack: StateRolledBack,
	},
	StateRolledBack: {
		EventReenter: StateSubmitted,
		EventExpire:  StateExpired,
	},
}

// next returns the state an event leads to, or false if the state does not
// accept it.
func next(s State, e Event) (State, bool) {
	to, ok := transitions[s][e]
	return to, ok
}

// Final reports whether no event leaves s. Only the unsuccessful final
// states release the draft's inputs.
func (s State) Final() bool {
	return s == StateCancelled || s == StateRejected || s == StateExpired || s == StateFailed
}

// Live reports whether the draft is still on its way: it holds its inputs and
// counts towards the policy's maximum of live drafts. A confirmed draft has
// arrived; it keeps its inputs only because they are spent.
func (s State) Live() bool {
	return !s.Final() && s != StateConfirmed
}

// StateError reports an event the draft's state does not accept.
type StateError struct {
	State State
	Event Event
}

func (e *StateError) Error() string {
	return fmt.Sprintf("drafts: a %s draft does not accept %s", e.State, e.Event)
}
