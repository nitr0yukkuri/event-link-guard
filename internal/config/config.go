package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"event-link-guard/internal/moderation"
)

type Config struct {
	Token string
	GoogleKey string
	LogChannel string
	Scope moderation.Scope
	Policy moderation.Policy
}

func channels(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" { out[id] = true }
	}
	return out
}

func boolean(name string) (bool, error) {
	switch os.Getenv(name) {
	case "", "false": return false, nil
	case "true": return true, nil
	default: return false, errors.New(name+" must be true or false")
	}
}

func validID(id string) bool {
	n, err := strconv.ParseUint(id, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == id
}

func Load() (Config, error) {
	c := Config{Token: os.Getenv("DISCORD_TOKEN"), GoogleKey: os.Getenv("GOOGLE_API_KEY"), LogChannel: os.Getenv("DISCORD_LOG_CHANNEL_ID")}
	c.Scope.GuildID = os.Getenv("DISCORD_GUILD_ID")
	c.Scope.URLChannels = channels(os.Getenv("DISCORD_CHANNEL_IDS"))
	c.Scope.SpamChannels = c.Scope.URLChannels
	if raw := strings.TrimSpace(os.Getenv("SPAM_CHANNEL_IDS")); raw != "" { c.Scope.SpamChannels = channels(raw) }
	if c.Token == "" || c.GoogleKey == "" || !validID(c.Scope.GuildID) || !validID(c.LogChannel) { return Config{}, errors.New("missing credentials or invalid Discord IDs") }
	for _, group := range []map[string]bool{c.Scope.URLChannels, c.Scope.SpamChannels} {
		if len(group) == 0 || group[c.LogChannel] { return Config{}, errors.New("empty channel list or monitored log channel") }
		for id := range group { if !validID(id) { return Config{}, errors.New("invalid monitored channel ID") } }
	}
	ack, err := boolean("ACK_URL_SHARING")
	if err != nil { return Config{}, err }
	if !ack { return Config{}, errors.New("review privacy notice before enabling URL sharing") }
	if c.Policy.EnforceURL, err = boolean("ENFORCE"); err != nil { return Config{}, err }
	if c.Policy.EnforceSpam, err = boolean("SPAM_ENFORCE"); err != nil { return Config{}, err }
	return c, nil
}
