// Package discord translates Gateway events and REST operations at the boundary.
package discord

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
	"event-link-guard/internal/moderation"
	"github.com/bwmarrin/discordgo"
)

type Adapter struct {
	session *discordgo.Session
	logChannel string
}

func New(token, logChannel string) (*Adapter, error) {
	s, err := discordgo.New("Bot " + token)
	if err != nil { return nil, err }
	s.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent
	// Preserve Gateway delivery order for the local detector. Handlers do not call REST.
	s.SyncEvents = true
	s.Client.Timeout = 10*time.Second
	return &Adapter{session: s, logChannel: logChannel}, nil
}

func message(m *discordgo.Message) moderation.Message {
	out := moderation.Message{Ref: moderation.Ref{ChannelID: m.ChannelID, MessageID: m.ID}, GuildID: m.GuildID, Content: m.Content, Automated: m.WebhookID != ""}
	if m.Author != nil {
		out.UserID = m.Author.ID
		out.Automated = out.Automated || m.Author.Bot
	}
	return out
}

func (a *Adapter) Open(ctx context.Context, inbound moderation.Inbound) error {
	a.session.AddHandler(func(_ *discordgo.Session, e *discordgo.MessageCreate) {
		if e.Message != nil { inbound.OnCreate(ctx, message(e.Message)) }
	})
	a.session.AddHandler(func(_ *discordgo.Session, e *discordgo.MessageUpdate) {
		if e.Message != nil {
			inbound.OnEdit(ctx, e.GuildID, moderation.Ref{ChannelID: e.ChannelID, MessageID: e.ID})
		}
	})
	return a.session.Open()
}

func (a *Adapter) Close() error { return a.session.Close() }

func (a *Adapter) Read(ctx context.Context, ref moderation.Ref) (moderation.Message, error) {
	m, err := a.session.ChannelMessage(ref.ChannelID, ref.MessageID, discordgo.WithContext(ctx), discordgo.WithRetryOnRatelimit(false))
	if err != nil { return moderation.Message{}, err }
	return message(m), nil
}

func (a *Adapter) Delete(ctx context.Context, ref moderation.Ref) error {
	err := a.session.ChannelMessageDelete(ref.ChannelID, ref.MessageID, discordgo.WithContext(ctx), discordgo.WithRetryOnRatelimit(false))
	var rest *discordgo.RESTError
	// Unknown Message (10008) means another actor already removed it.
	if errors.As(err, &rest) && rest.Response != nil && rest.Response.StatusCode == http.StatusNotFound && rest.Message != nil && rest.Message.Code == 10008 { return nil }
	return err
}

func (a *Adapter) Notify(ctx context.Context, audit moderation.Audit) error {
	content := fmt.Sprintf("検知: %s / %s\nchannel: `%s` message: `%s` user: `%s`\nreason: `%s` count: %d", audit.Kind, audit.Outcome, audit.ChannelID, audit.MessageID, audit.UserID, audit.Reason, audit.Count)
	if audit.Kind == "THREAT_MATCH" {
		content += "\n危険な可能性があります。検知の正確性は保証されません。 Advisory provided by Google: <https://developers.google.com/safe-browsing/v4/advisory>"
	}
	_, err := a.session.ChannelMessageSendComplex(a.logChannel, &discordgo.MessageSend{Content: content, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}}, discordgo.WithContext(ctx), discordgo.WithRetryOnRatelimit(false))
	return err
}

var _ moderation.MessageReader = (*Adapter)(nil)
var _ moderation.Actions = (*Adapter)(nil)
