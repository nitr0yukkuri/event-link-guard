package moderation

import (
	"context"
	"event-link-guard/internal/guard"
	"event-link-guard/internal/spam"
	"testing"
)

type checker guard.Verdict
func (c checker) Check(context.Context, string) guard.Verdict { return guard.Verdict(c) }

type fakeAdapter struct {
	current Message
	reads int
	deletes int
	audits []Audit
}
func (f *fakeAdapter) Read(context.Context, Ref) (Message, error) { f.reads++; return f.current, nil }
func (f *fakeAdapter) Delete(context.Context, Ref) error { f.deletes++; return nil }
func (f *fakeAdapter) Notify(_ context.Context, a Audit) error { f.audits = append(f.audits, a); return nil }

func fixture(p Policy, verdict guard.Verdict) (*Service, *fakeAdapter, Message) {
	m := Message{Ref: Ref{ChannelID: "c", MessageID: "m"}, GuildID: "g", UserID: "u", Content: "https://example.com/event"}
	f := &fakeAdapter{current: m}
	s := New(Scope{GuildID: "g", URLChannels: map[string]bool{"c": true}, SpamChannels: map[string]bool{"c": true}}, p, f, f, checker(verdict))
	return s, f, m
}

func TestCreateFilters(t *testing.T) {
	s, f, m := fixture(Policy{}, guard.NoMatch)
	ctx := context.Background()
	plain := m
	plain.Content = "hello"
	plain.MessageID = "plain"
	s.OnCreate(ctx, plain)
	bot := m
	bot.Automated = true
	s.OnCreate(ctx, bot)
	other := m
	other.GuildID = "other"
	s.OnCreate(ctx, other)
	if len(s.urls) != 0 || f.reads != 0 { t.Fatal("irrelevant event queued") }
	s.OnCreate(ctx, m)
	s.OnCreate(ctx, m)
	if len(s.urls) != 1 { t.Fatal("expected one job") }
	s.processURL(ctx, <-s.urls)
	if f.reads != 0 || f.deletes != 0 || len(f.audits) != 0 { t.Fatal("unnecessary side effects") }
}

func TestURLPolicyAndRecheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		verdict guard.Verdict
		enforce, changed bool
		reads, deletes, audits int
	}{
		{"monitor", guard.Threat, false, false, 0, 0, 1},
		{"unknown", guard.Unknown, true, false, 0, 0, 1},
		{"confirmed", guard.Threat, true, false, 1, 1, 1},
		{"changed", guard.Threat, true, true, 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, m := fixture(Policy{EnforceURL: tc.enforce}, tc.verdict)
			if tc.changed { f.current.Content = "edited" }
			s.processURL(context.Background(), urlJob{message: m})
			if f.reads != tc.reads || f.deletes != tc.deletes || len(f.audits) != tc.audits { t.Fatalf("unexpected actions: %+v", f) }
		})
	}
}

func TestEditRefresh(t *testing.T) {
	s, f, m := fixture(Policy{}, guard.NoMatch)
	s.OnEdit(context.Background(), m.GuildID, m.Ref)
	s.processURL(context.Background(), <-s.urls)
	if f.reads != 1 || f.deletes != 0 { t.Fatal("expected only refresh") }
}

func TestSpamPolicy(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		s, f, m := fixture(Policy{EnforceSpam: enforce}, guard.NoMatch)
		s.processSpam(context.Background(), spamJob{message: m, result: spam.Result{Reason: spam.Burst, Count: 6, Alert: true}})
		if (f.deletes == 1) != enforce || len(f.audits) != 1 || f.reads != 0 { t.Fatalf("unexpected actions: %+v", f) }
	}
}
