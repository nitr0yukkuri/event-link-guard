package moderation

import (
	"context"
	"event-link-guard/internal/guard"
	"event-link-guard/internal/spam"
	"log/slog"
	"sync"
	"time"
)

type Scope struct {
	GuildID string
	URLChannels map[string]bool
	SpamChannels map[string]bool
}

type urlJob struct {
	message Message
	refresh bool
}

type spamJob struct {
	message Message
	result spam.Result
}

type Service struct {
	scope Scope
	policy Policy
	reader MessageReader
	actions Actions
	checker guard.Checker
	detector *spam.Detector
	urls chan urlJob
	spam chan spamJob
}

func New(scope Scope, policy Policy, reader MessageReader, actions Actions, checker guard.Checker) *Service {
	return &Service{
		scope: Scope{GuildID: scope.GuildID, URLChannels: clone(scope.URLChannels), SpamChannels: clone(scope.SpamChannels)},
		policy: policy, reader: reader, actions: actions, checker: checker, detector: spam.New(),
		urls: make(chan urlJob, 64), spam: make(chan spamJob, 128),
	}
}

func clone(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in { out[k] = v }
	return out
}

func eligible(m Message) bool {
	return m.ChannelID != "" && m.MessageID != "" && m.UserID != "" && !m.Automated
}

func (s *Service) OnCreate(ctx context.Context, m Message) {
	if ctx.Err() != nil || m.GuildID != s.scope.GuildID || !eligible(m) { return }
	if s.scope.SpamChannels[m.ChannelID] {
		r := s.detector.Observe(m.UserID, m.MessageID, m.Content)
		if r.Duplicate { return }
		if r.CapacityExceeded { slog.Warn("spam detector capacity exceeded") }
		d := s.policy.Spam(r)
		if r.Reason != "" {
			slog.Info("spam detection", "message", m.MessageID, "reason", r.Reason, "count", r.Count)
		}
		if d.Delete || d.Notify {
			// No raw content is required for a frequency-based action.
			mCopy := m
			mCopy.Content = ""
			select {
			case <-ctx.Done():
			case s.spam <- spamJob{mCopy, r}:
			default: slog.Warn("spam queue full", "message", m.MessageID)
			}
		}
	}
	if s.scope.URLChannels[m.ChannelID] && len(guard.Extract(m.Content)) > 0 {
		s.enqueueURL(ctx, urlJob{message: m})
	}
}

func (s *Service) OnEdit(ctx context.Context, guildID string, ref Ref) {
	if ctx.Err() != nil || guildID != s.scope.GuildID || !s.scope.URLChannels[ref.ChannelID] || ref.MessageID == "" { return }
	// Discord update events may be partial. Fetch only for edits, not every create.
	s.enqueueURL(ctx, urlJob{message: Message{Ref: ref, GuildID: guildID}, refresh: true})
}

func (s *Service) enqueueURL(ctx context.Context, j urlJob) {
	select {
	case <-ctx.Done():
	case s.urls <- j:
	default: slog.Warn("URL queue full", "message", j.message.MessageID)
	}
}

// Run owns both bounded workers and returns after cancellation. Call once.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done(): return
			case j := <-s.urls: s.processURL(ctx, j)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done(): return
			case j := <-s.spam: s.processSpam(ctx, j)
			}
		}
	}()
	wg.Wait()
}

func (s *Service) read(ctx context.Context, ref Ref) (Message, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.reader.Read(c, ref)
}

func (s *Service) delete(ctx context.Context, ref Ref) string {
	if ctx.Err() != nil { return "cancelled" }
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.actions.Delete(c, ref); err != nil { return "delete_failed" }
	return "deleted_or_already_absent"
}

func (s *Service) report(ctx context.Context, a Audit, notify bool) {
	slog.Info("moderation action", "message", a.MessageID, "channel", a.ChannelID, "kind", a.Kind, "reason", a.Reason, "outcome", a.Outcome)
	if !notify || ctx.Err() != nil { return }
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.actions.Notify(c, a); err != nil { slog.Warn("audit notification failed", "message", a.MessageID) }
}

func (s *Service) processSpam(ctx context.Context, j spamJob) {
	if ctx.Err() != nil { return }
	d := s.policy.Spam(j.result)
	outcome := "retained"
	if d.Delete { outcome = s.delete(ctx, j.message.Ref) }
	s.report(ctx, Audit{Ref: j.message.Ref, UserID: j.message.UserID, Kind: "spam", Reason: string(j.result.Reason), Count: j.result.Count, Outcome: outcome}, d.Notify)
}

func (s *Service) processURL(ctx context.Context, j urlJob) {
	if ctx.Err() != nil { return }
	m := j.message
	if j.refresh {
		var err error
		m, err = s.read(ctx, m.Ref)
		if err != nil { slog.Warn("message fetch failed", "message", j.message.MessageID); return }
	}
	if m.Ref != j.message.Ref || !eligible(m) || (m.GuildID != "" && m.GuildID != s.scope.GuildID) { return }
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	r := guard.Inspect(c, s.checker, m.Content)
	cancel()
	d := s.policy.URL(r)
	if !d.Delete && !d.Notify { return }
	outcome := "retained"
	if d.Delete {
		current, err := s.read(ctx, m.Ref)
		if err == nil && current.Ref == m.Ref && eligible(current) && current.UserID == m.UserID && current.Content == m.Content && (current.GuildID == "" || current.GuildID == s.scope.GuildID) {
			outcome = s.delete(ctx, m.Ref)
		} else { outcome = "changed_or_unavailable" }
	}
	s.report(ctx, Audit{Ref: m.Ref, UserID: m.UserID, Kind: string(r.Verdict), Reason: r.Reason, Count: r.Count, Outcome: outcome}, d.Notify)
}
