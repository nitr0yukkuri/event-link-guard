// Package moderation coordinates detection and policy without depending on Discord.
package moderation

import "context"

type Ref struct {
	ChannelID string
	MessageID string
}

type Message struct {
	Ref
	GuildID string
	UserID string
	Content string
	Automated bool
}

type Audit struct {
	Ref
	UserID string
	Kind string
	Reason string
	Outcome string
	Count int
}

// MessageReader retrieves the current message for partial edits and deletion checks.
type MessageReader interface {
	Read(context.Context, Ref) (Message, error)
}

// Actions deliberately expose only the side effects the application needs.
type Actions interface {
	Delete(context.Context, Ref) error
	Notify(context.Context, Audit) error
}

// Inbound is the port used by Gateway adapters.
type Inbound interface {
	OnCreate(context.Context, Message)
	OnEdit(context.Context, string, Ref)
}
