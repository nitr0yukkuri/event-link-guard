package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"event-link-guard/internal/rolepicker"
	"github.com/bwmarrin/discordgo"
)

func main() {
	cfg, err := rolepicker.Load()
	if err != nil {
		slog.Error("invalid role-picker configuration", "error", err)
		os.Exit(1)
	}

	session, err := discordgo.New("Bot " + cfg.Token)
	if err != nil {
		slog.Error("create Discord session", "error", err)
		os.Exit(1)
	}
	session.Identify.Intents = discordgo.IntentsGuilds

	readyCh := make(chan *discordgo.Ready, 1)
	session.AddHandler(func(_ *discordgo.Session, event *discordgo.Ready) {
		select {
		case readyCh <- event:
		default:
		}
	})
	session.AddHandler(func(s *discordgo.Session, event *discordgo.InteractionCreate) {
		if event == nil || event.Interaction == nil {
			return
		}
		if err := cfg.HandleInteraction(s, event, event.AppID); err != nil {
			slog.Warn("handle Discord interaction", "error", err)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := session.Open(); err != nil {
		slog.Error("open Discord Gateway connection", "error", err)
		return
	}
	defer session.Close()

	var ready *discordgo.Ready
	select {
	case ready = <-readyCh:
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
		slog.Error("timed out waiting for Discord Ready event")
		return
	}
	if ready == nil || ready.User == nil {
		slog.Error("Discord Ready event did not include the bot user")
		return
	}

	if err := cfg.Resolve(session); err != nil {
		slog.Error("role-picker setup check failed", "error", err)
		return
	}
	if err := registerPanelCommand(session, ready.User.ID, cfg.GuildID); err != nil {
		slog.Error("register /role-panel command", "error", err)
		return
	}

	slog.Info("role picker is ready", "guild", cfg.GuildID, "channel", cfg.ChannelID, "roles", len(cfg.Roles))
	<-ctx.Done()
}

func registerPanelCommand(s *discordgo.Session, appID, guildID string) error {
	commands, err := s.ApplicationCommands(appID, guildID)
	if err != nil {
		return err
	}
	permissions := int64(discordgo.PermissionManageGuild)
	command := &discordgo.ApplicationCommand{
		Name:                     "role-panel",
		Description:              "ロール選択パネルを作成・更新します",
		DefaultMemberPermissions: &permissions,
	}
	for _, existing := range commands {
		if existing.Name == command.Name {
			_, err = s.ApplicationCommandEdit(appID, guildID, existing.ID, command)
			return err
		}
	}
	_, err = s.ApplicationCommandCreate(appID, guildID, command)
	return err
}
