package main

import (
	"context"
	"event-link-guard/internal/guard"
	"event-link-guard/internal/spam"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type job struct{ channel, id string }
type spamJob struct {
	channel, id, user string
	result            spam.Result
}

func main() {
	token, key, guild, logChannel := os.Getenv("DISCORD_TOKEN"), os.Getenv("GOOGLE_API_KEY"), os.Getenv("DISCORD_GUILD_ID"), os.Getenv("DISCORD_LOG_CHANNEL_ID")
	channels := map[string]bool{}
	for _, v := range strings.Split(os.Getenv("DISCORD_CHANNEL_IDS"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			channels[v] = true
		}
	}
	if token == "" || key == "" || guild == "" || logChannel == "" || len(channels) == 0 || channels[logChannel] {
		slog.Error("required config missing or log channel is monitored")
		os.Exit(1)
	}
	if os.Getenv("ACK_URL_SHARING") != "true" {
		slog.Error("review privacy notice before enabling URL sharing")
		os.Exit(1)
	}
	enforce := os.Getenv("ENFORCE") == "true"
	spamEnforce := os.Getenv("SPAM_ENFORCE") == "true"
	spamChannels := channels
	if raw := strings.TrimSpace(os.Getenv("SPAM_CHANNEL_IDS")); raw != "" {
		spamChannels = map[string]bool{}
		for _, v := range strings.Split(raw, ",") {
			if v = strings.TrimSpace(v); v != "" {
				spamChannels[v] = true
			}
		}
	}
	if len(spamChannels) == 0 || spamChannels[logChannel] {
		slog.Error("invalid spam channel config")
		os.Exit(1)
	}
	detector := spam.New()
	spamJobs := make(chan spamJob, 128)
	s, err := discordgo.New("Bot " + token)
	if err != nil {
		slog.Error("discord setup failed")
		os.Exit(1)
	}
	s.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent
	checker := guard.NewGoogle(key)
	jobs := make(chan job, 64)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var wg sync.WaitGroup
	enqueue := func(g, c, id string) {
		if g != guild || !channels[c] || id == "" {
			return
		}
		select {
		case <-ctx.Done():
		case jobs <- job{c, id}:
		default:
			slog.Warn("queue full; message not inspected", "channel", c, "message", id)
		}
	}
	s.AddHandler(func(_ *discordgo.Session, e *discordgo.MessageCreate) {
		if e.Message != nil {
			if e.GuildID == guild && spamChannels[e.ChannelID] && e.Author != nil && !e.Author.Bot && e.WebhookID == "" {
				r := detector.Observe(e.Author.ID, e.ID, e.Content)
				if r.CapacityExceeded {
					slog.Warn("spam detector capacity exceeded")
				}
				if r.Reason != "" {
					slog.Info("spam detection", "message", e.ID, "user", e.Author.ID, "reason", r.Reason, "count", r.Count)
					if r.Alert || spamEnforce {
						select {
						case <-ctx.Done():
						case spamJobs <- spamJob{e.ChannelID, e.ID, e.Author.ID, r}:
						default:
							slog.Warn("spam action queue full", "message", e.ID)
						}
					}
				}
			}
			enqueue(e.GuildID, e.ChannelID, e.ID)
		}
	})
	s.AddHandler(func(_ *discordgo.Session, e *discordgo.MessageUpdate) {
		if e.Message != nil {
			enqueue(e.GuildID, e.ChannelID, e.ID)
		}
	})
	// Spam actions run independently of slow external URL lookups.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-spamJobs:
				action := "retained"
				if spamEnforce && ctx.Err() == nil {
					if err := s.ChannelMessageDelete(j.channel, j.id); err != nil {
						action = "delete_failed"
					} else {
						action = "deleted"
					}
				}
				slog.Info("spam action", "message", j.id, "reason", j.result.Reason, "action", action)
				if j.result.Alert && ctx.Err() == nil {
					msg := fmt.Sprintf("連投検知: %s / %s\nuser: `%s` channel: `%s` message: `%s`\ncount: %d（同一ユーザーの通知は30秒間抑制）", j.result.Reason, action, j.user, j.channel, j.id, j.result.Count)
					if _, err := s.ChannelMessageSendComplex(logChannel, &discordgo.MessageSend{Content: msg, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}}); err != nil {
						slog.Warn("spam audit notification failed", "message", j.id)
					}
				}
			}
		}
	}()
	// One URL worker keeps external API load bounded.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-jobs:
				m, err := s.ChannelMessage(j.channel, j.id)
				if err != nil {
					slog.Warn("message fetch failed", "message", j.id)
					continue
				}
				if m.Author == nil || m.Author.Bot || m.WebhookID != "" {
					continue
				}
				if len(guard.Extract(m.Content)) == 0 {
					continue
				}
				c, done := context.WithTimeout(ctx, 12*time.Second)
				r := guard.Inspect(c, checker, m.Content)
				done()
				if r.Verdict == guard.NoMatch {
					continue
				}
				action := "retained"
				if r.Verdict == guard.Threat && enforce {
					current, err := s.ChannelMessage(j.channel, j.id)
					if err == nil && current.Content == m.Content && ctx.Err() == nil {
						if err = s.ChannelMessageDelete(j.channel, j.id); err == nil {
							action = "deleted"
						} else {
							action = "delete_failed"
						}
					} else {
						action = "changed_or_unavailable"
					}
				}
				slog.Info("inspection", "message", j.id, "channel", j.channel, "verdict", r.Verdict, "action", action, "reason", r.Reason)
				// No user content, URL, mention or secret is re-published.
				msg := fmt.Sprintf("URL検査: %s / %s\nchannel: `%s` message: `%s`\nreason: `%s`", r.Verdict, action, j.channel, j.id, r.Reason)
				if r.Verdict == guard.Threat {
					msg += "\n危険な可能性があります。検知の正確性は保証されません。 Advisory provided by Google: <https://developers.google.com/safe-browsing/v4/advisory>"
				}
				if _, err = s.ChannelMessageSendComplex(logChannel, &discordgo.MessageSend{Content: msg, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}}); err != nil {
					slog.Warn("audit notification failed", "message", j.id)
				}
			}
		}
	}()
	if err = s.Open(); err != nil {
		slog.Error("discord gateway connection failed")
		cancel()
		wg.Wait()
		os.Exit(1)
	}
	slog.Info("started", "enforce", enforce, "spam_enforce", spamEnforce)
	<-ctx.Done()
	_ = s.Close()
	wg.Wait()
}
