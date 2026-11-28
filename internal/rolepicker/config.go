package rolepicker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
)

type Role struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Label    string `json:"label"`
	Emoji    string `json:"emoji"`
	ID       string `json:"-"`
}

type Config struct {
	Token           string
	GuildID         string
	ChannelID       string
	PanelMessageID  string
	Roles           []Role
}

func Load() (Config, error) {
	cfg := Config{
		Token:          strings.TrimSpace(os.Getenv("ROLE_PICKER_TOKEN")),
		GuildID:        strings.TrimSpace(os.Getenv("ROLE_PICKER_GUILD_ID")),
		ChannelID:      strings.TrimSpace(os.Getenv("ROLE_PICKER_CHANNEL_ID")),
		PanelMessageID: strings.TrimSpace(os.Getenv("ROLE_PICKER_PANEL_MESSAGE_ID")),
	}
	rawRoles := strings.TrimSpace(os.Getenv("ROLE_PICKER_ROLES_JSON"))
	if cfg.Token == "" || !isSnowflake(cfg.GuildID) || !isSnowflake(cfg.ChannelID) {
		return Config{}, fmt.Errorf("ROLE_PICKER_TOKEN, ROLE_PICKER_GUILD_ID, and ROLE_PICKER_CHANNEL_ID are required")
	}
	if cfg.PanelMessageID != "" && !isSnowflake(cfg.PanelMessageID) {
		return Config{}, fmt.Errorf("ROLE_PICKER_PANEL_MESSAGE_ID must be a Discord snowflake")
	}
	if rawRoles == "" {
		return Config{}, fmt.Errorf("ROLE_PICKER_ROLES_JSON is required")
	}
	if err := json.Unmarshal([]byte(rawRoles), &cfg.Roles); err != nil {
		return Config{}, fmt.Errorf("parse ROLE_PICKER_ROLES_JSON: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if len(c.Roles) == 0 || len(c.Roles) > 25 {
		return fmt.Errorf("configure between 1 and 25 roles; Discord select menus support at most 25")
	}

	names := make(map[string]bool, len(c.Roles))
	labels := make(map[string]bool, len(c.Roles))
	for i, role := range c.Roles {
		if strings.TrimSpace(role.Category) == "" || strings.TrimSpace(role.Name) == "" || strings.TrimSpace(role.Label) == "" {
			return fmt.Errorf("role %d must have category, name, and label", i+1)
		}
		if utf8.RuneCountInString(role.Category) > 100 || utf8.RuneCountInString(role.Label) > 100 {
			return fmt.Errorf("role %d category and label must be at most 100 characters", i+1)
		}
		if utf8.RuneCountInString(role.Emoji) > 100 {
			return fmt.Errorf("role %d emoji must be at most 100 characters", i+1)
		}
		if names[role.Name] {
			return fmt.Errorf("duplicate configured role name %q", role.Name)
		}
		if labels[role.Label] {
			return fmt.Errorf("duplicate role label %q; labels must be unique", role.Label)
		}
		names[role.Name] = true
		labels[role.Label] = true
	}
	if utf8.RuneCountInString(c.panelContent()) > 2000 {
		return fmt.Errorf("the rendered role panel exceeds Discord's 2000-character message limit")
	}
	return nil
}

func isSnowflake(value string) bool {
	if len(value) < 16 || len(value) > 22 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (c *Config) Resolve(s *discordgo.Session) error {
	serverRoles, err := s.GuildRoles(c.GuildID)
	if err != nil {
		return fmt.Errorf("load server roles: %w", err)
	}
	botMember, err := s.UserGuildMember(c.GuildID)
	if err != nil {
		return fmt.Errorf("load bot's server membership: %w", err)
	}
	channel, err := s.Channel(c.ChannelID)
	if err != nil {
		return fmt.Errorf("load configured role channel: %w", err)
	}
	if channel.GuildID != c.GuildID {
		return fmt.Errorf("ROLE_PICKER_CHANNEL_ID must belong to ROLE_PICKER_GUILD_ID")
	}

	rolesByID := make(map[string]*discordgo.Role, len(serverRoles))
	for _, role := range serverRoles {
		rolesByID[role.ID] = role
	}

	botPermissions := int64(0)
	if everyone, ok := rolesByID[c.GuildID]; ok {
		botPermissions |= everyone.Permissions
	}
	botTopPosition := -1
	for _, roleID := range botMember.Roles {
		role, ok := rolesByID[roleID]
		if !ok {
			return fmt.Errorf("bot role %s was not returned by Discord", roleID)
		}
		botPermissions |= role.Permissions
		if role.Position > botTopPosition {
			botTopPosition = role.Position
		}
	}
	if botPermissions&(discordgo.PermissionManageRoles|discordgo.PermissionAdministrator) == 0 {
		return fmt.Errorf("the bot needs Manage Roles permission")
	}
	if botTopPosition < 0 {
		return fmt.Errorf("could not determine the bot's highest role position")
	}

	for i := range c.Roles {
		var match *discordgo.Role
		matches := 0
		for _, role := range serverRoles {
			if role.Name == c.Roles[i].Name {
				match = role
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("configured server role %q must match exactly one role (found %d)", c.Roles[i].Name, matches)
		}
		if match.ID == c.GuildID || match.Managed {
			return fmt.Errorf("configured role %q is an everyone or integration-managed role", match.Name)
		}
		if match.Permissions != 0 {
			return fmt.Errorf("configured role %q has permissions; self-selectable roles must have no permissions", match.Name)
		}
		if match.Position >= botTopPosition {
			return fmt.Errorf("move the bot's highest role above configured role %q", match.Name)
		}
		c.Roles[i].ID = match.ID
	}
	return nil
}

func (c Config) panelContent() string {
	var b strings.Builder
	b.WriteString("# ロール選択\n")
	b.WriteString("参加地域や興味のあるテーマを選んでください。複数選択できます。\n\n")

	seen := make(map[string]bool, len(c.Roles))
	for _, role := range c.Roles {
		if seen[role.Category] {
			continue
		}
		seen[role.Category] = true
		b.WriteString("**")
		b.WriteString(role.Category)
		b.WriteString("**\n")
		items := make([]string, 0)
		for _, item := range c.Roles {
			if item.Category != role.Category {
				continue
			}
			label := item.Label
			if item.Emoji != "" {
				label = item.Emoji + " " + label
			}
			items = append(items, label)
		}
		b.WriteString(strings.Join(items, "　／　"))
		b.WriteString("\n\n")
	}

	b.WriteString("下のボタンを押すと、自分だけに見える選択画面が開きます。選択を送信すると、このパネルに載っているロールだけが更新されます。")
	return b.String()
}

func (c Config) PanelContent() string {
	return c.panelContent()
}

func (c Config) PanelComponents() []discordgo.MessageComponent {
	return []discordgo.MessageComponent{
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.Button{
					Label:    "ロールを選ぶ",
					Style:    discordgo.PrimaryButton,
					CustomID: openCustomID,
				},
			},
		},
	}
}

func (c Config) PickerComponents(selected map[string]bool) []discordgo.MessageComponent {
	options := make([]discordgo.SelectMenuOption, 0, len(c.Roles))
	for _, role := range c.Roles {
		option := discordgo.SelectMenuOption{
			Label:       role.Label,
			Value:       role.ID,
			Description: role.Category,
			Default:     selected[role.ID],
		}
		if role.Emoji != "" {
			option.Emoji = &discordgo.ComponentEmoji{Name: role.Emoji}
		}
		options = append(options, option)
	}
	minValues := 0
	return []discordgo.MessageComponent{
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.SelectMenu{
					MenuType:    discordgo.StringSelectMenu,
					CustomID:    applyCustomID,
					Placeholder: "参加したい地域・テーマを選択",
					MinValues:   &minValues,
					MaxValues:   len(options),
					Options:     options,
				},
			},
		},
	}
}

const (
	openCustomID  = "event-link-guard:rolepicker:open:v1"
	applyCustomID = "event-link-guard:rolepicker:apply:v1"
)
