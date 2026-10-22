// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

// message is what the protocol knows of a message type: the sockets that
// accept it and the types of its request and response bodies.
type message struct {
	service, admin bool
	req, resp      func() Body
}

func (m message) on(s Socket) bool {
	return (s == Service && m.service) || (s == Admin && m.admin)
}

var messages = map[string]message{
	MsgHello:             {true, true, func() Body { return new(Hello) }, func() Body { return new(Hello) }},
	MsgSignDraft:         {true, false, func() Body { return new(SignDraft) }, func() Body { return new(SignDraftResult) }},
	MsgCreateWallet:      {true, false, func() Body { return new(CreateWallet) }, func() Body { return new(WalletCreated) }},
	MsgGetApprovalStatus: {true, false, func() Body { return new(GetApprovalStatus) }, func() Body { return new(ApprovalStatus) }},
	MsgGetPolicyStatus:   {true, false, func() Body { return new(GetPolicyStatus) }, func() Body { return new(PolicyStatus) }},
	MsgPing:              {true, false, func() Body { return new(Empty) }, func() Body { return new(PingResult) }},
	MsgListWallets:       {true, false, func() Body { return new(Empty) }, func() Body { return new(WalletList) }},

	MsgStatus:                {false, true, func() Body { return new(Empty) }, func() Body { return new(StatusReport) }},
	MsgUnlock:                {false, true, func() Body { return new(Unlock) }, func() Body { return new(Empty) }},
	MsgBeginAuthorization:    {false, true, func() Body { return new(BeginAuthorization) }, func() Body { return new(Challenge) }},
	MsgCompleteAuthorization: {false, true, func() Body { return new(CompleteAuthorization) }, func() Body { return new(Completed) }},
	MsgReject:                {false, true, func() Body { return new(ApprovalRef) }, func() Body { return new(Empty) }},
	MsgFreeze:                {false, true, func() Body { return new(Freeze) }, func() Body { return new(Empty) }},
	MsgCloseSession:          {false, true, func() Body { return new(WalletRef) }, func() Body { return new(Empty) }},
	MsgListExpired:           {false, true, func() Body { return new(ListExpired) }, func() Body { return new(ExpiredList) }},
	MsgShowPolicy:            {false, true, func() Body { return new(WalletRef) }, func() Body { return new(WalletPolicy) }},
	MsgShowTemplate:          {false, true, func() Body { return new(Empty) }, func() Body { return new(Template) }},
	MsgShowAudit:             {false, true, func() Body { return new(ShowAudit) }, func() Body { return new(AuditPage) }},
	MsgVerifyAudit:           {false, true, func() Body { return new(Empty) }, func() Body { return new(AuditCheck) }},
}

// NewRequest returns an empty request body for message type t, or nil if
// there is no such message.
func NewRequest(t string) Body {
	if m, ok := messages[t]; ok {
		return m.req()
	}
	return nil
}

// NewResponse returns an empty response body for message type t, or nil if
// there is no such message.
func NewResponse(t string) Body {
	if m, ok := messages[t]; ok {
		return m.resp()
	}
	return nil
}
