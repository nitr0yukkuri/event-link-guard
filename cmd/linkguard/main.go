package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"event-link-guard/internal/adapter/discord"
	"event-link-guard/internal/adapter/safebrowsing"
	"event-link-guard/internal/config"
	"event-link-guard/internal/moderation"
)

func run() int {
	cfg, err := config.Load()
	if err != nil { slog.Error("configuration rejected", "reason", err.Error()); return 1 }
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	adapter, err := discord.New(cfg.Token, cfg.LogChannel)
	if err != nil { slog.Error("discord setup failed"); return 1 }
	service := moderation.New(cfg.Scope, cfg.Policy, adapter, adapter, safebrowsing.NewGoogle(cfg.GoogleKey))
	done := make(chan struct{})
	go func() { defer close(done); service.Run(ctx) }()
	if err := adapter.Open(ctx, service); err != nil {
		slog.Error("discord gateway connection failed")
		cancel()
		<-done
		_ = adapter.Close()
		return 1
	}
	slog.Info("started", "enforce_url", cfg.Policy.EnforceURL, "enforce_spam", cfg.Policy.EnforceSpam)
	<-ctx.Done()
	_ = adapter.Close()
	<-done
	return 0
}

func main() { os.Exit(run()) }
