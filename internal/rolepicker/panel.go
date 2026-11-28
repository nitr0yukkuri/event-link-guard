package rolepicker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bwmarrin/discordgo"
)

func (c Config) UpsertPanel(s *discordgo.Session, botID string) (*discordgo.Message, error) {
	var existing *discordgo.Message
	if c.PanelMessageID != "" {
		message, err := s.ChannelMessage(c.ChannelID, c.PanelMessageID)
		if err != nil {
			return nil, fmt.Errorf("load configured panel message: %w", err)
		}
		if !isOwnPanel(message, botID) {
			return nil, fmt.Errorf("configured panel message is not a role-picker panel authored by this bot")
		}
		existing = message
	} else {
		messages, err := s.ChannelMessages(c.ChannelID, 100, "", "", "")
		if err != nil {
			return nil, fmt.Errorf("search role channel history: %w", err)
		}
		for _, message := range messages {
			if isOwnPanel(message, botID) {
				existing = message
				break
			}
		}
	}

	content := c.PanelContent()
	components := c.PanelComponents()
	if existing != nil {
		updated, err := s.ChannelMessageEditComplex(&discordgo.MessageEdit{
			ID:         existing.ID,
			Channel:    c.ChannelID,
			Content:    &content,
			Components: &components,
		})
		if err != nil {
			return nil, fmt.Errorf("edit role-picker panel: %w", err)
		}
		return updated, nil
	}

	message, err := s.ChannelMessageSendComplex(c.ChannelID, &discordgo.MessageSend{
		Content:         content,
		Components:      components,
		AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}},
	})
	if err != nil {
		return nil, fmt.Errorf("create role-picker panel: %w", err)
	}
	return message, nil
}

func isOwnPanel(message *discordgo.Message, botID string) bool {
	return isOwnMessageWithComponent(message, botID, openCustomID)
}

func isOwnMessageWithComponent(message *discordgo.Message, botID, customID string) bool {
	if message == nil || message.Author == nil || message.Author.ID != botID {
		return false
	}
	encoded, err := json.Marshal(message.Components)
	return err == nil && strings.Contains(string(encoded), customID)
}

func (c Config) HandleInteraction(s *discordgo.Session, event *discordgo.InteractionCreate, botID string) error {
	if event == nil || event.Interaction == nil {
		return nil
	}
	interaction := event.Interaction

	switch interaction.Type {
	case discordgo.InteractionApplicationCommand:
		data := interaction.ApplicationCommandData()
		if data.Name != "role-panel" {
			return nil
		}
		return c.handlePanelCommand(s, interaction, botID)
	case discordgo.InteractionMessageComponent:
		data := interaction.MessageComponentData()
		switch data.CustomID {
		case openCustomID:
			return c.handleOpenPicker(s, interaction, data, botID)
		case applyCustomID:
			return c.handleApply(s, interaction, data, botID)
		}
	}
	return nil
}

func (c Config) handlePanelCommand(s *discordgo.Session, interaction *discordgo.Interaction, botID string) error {
	if interaction.GuildID != c.GuildID {
		return respondEphemeral(s, interaction, "このコマンドは設定されたサーバー内でのみ使えます。", nil)
	}
	if interaction.Member == nil || interaction.Member.Permissions&discordgo.PermissionManageGuild == 0 {
		return respondEphemeral(s, interaction, "パネルの設置にはサーバー管理権限が必要です。", nil)
	}
	if err := s.InteractionRespond(interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	}); err != nil {
		return fmt.Errorf("acknowledge role-panel command: %w", err)
	}

	_, err := c.UpsertPanel(s, botID)
	reply := "ロール選択パネルを更新しました。"
	if err != nil {
		reply = "パネルを更新できませんでした。設定とチャンネル権限を確認してください。"
	}
	if _, editErr := s.InteractionResponseEdit(interaction, &discordgo.WebhookEdit{Content: &reply}); editErr != nil {
		if err != nil {
			return fmt.Errorf("panel update failed (%v); report result: %w", err, editErr)
		}
		return fmt.Errorf("report panel update: %w", editErr)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c Config) handleOpenPicker(s *discordgo.Session, interaction *discordgo.Interaction, _ discordgo.MessageComponentInteractionData, botID string) error {
	if interaction.GuildID != c.GuildID || !isOwnPanel(interaction.Message, botID) {
		return respondEphemeral(s, interaction, "このパネルは現在のサーバー設定と一致しません。", nil)
	}
	if interaction.Member == nil || interaction.Member.User == nil {
		return respondEphemeral(s, interaction, "サーバー内で選択してください。", nil)
	}
	if interaction.AppPermissions&discordgo.PermissionManageRoles == 0 {
		return respondEphemeral(s, interaction, "ボットにロール管理権限がありません。管理者に設定を確認してもらってください。", nil)
	}
	selected := make(map[string]bool, len(c.Roles))
	for _, role := range c.Roles {
		for _, memberRoleID := range interaction.Member.Roles {
			if memberRoleID == role.ID {
				selected[role.ID] = true
				break
			}
		}
	}
	content := "選びたい項目を複数選択し、選択を送信してください。ここに表示されるのは本人だけです。"
	return respondEphemeral(s, interaction, content, c.PickerComponents(selected))
}

func (c Config) handleApply(s *discordgo.Session, interaction *discordgo.Interaction, data discordgo.MessageComponentInteractionData, botID string) error {
	if interaction.GuildID != c.GuildID || !isOwnMessageWithComponent(interaction.Message, botID, applyCustomID) {
		return respondEphemeral(s, interaction, "この選択画面は現在のサーバー設定と一致しません。", nil)
	}
	if interaction.Member == nil || interaction.Member.User == nil {
		return respondEphemeral(s, interaction, "サーバー内で選択してください。", nil)
	}
	if interaction.AppPermissions&discordgo.PermissionManageRoles == 0 {
		return respondEphemeral(s, interaction, "ボットにロール管理権限がありません。管理者に設定を確認してもらってください。", nil)
	}

	allowed := make(map[string]bool, len(c.Roles))
	selected := make(map[string]bool, len(data.Values))
	for _, role := range c.Roles {
		allowed[role.ID] = true
	}
	for _, value := range data.Values {
		if !allowed[value] {
			return respondEphemeral(s, interaction, "選択に含まれるロールが設定にありません。画面を閉じて、もう一度開いてください。", nil)
		}
		selected[value] = true
	}
	if err := s.InteractionRespond(interaction, &discordgo.InteractionResponse{Type: discordgo.InteractionResponseDeferredMessageUpdate}); err != nil {
		return fmt.Errorf("acknowledge role selection: %w", err)
	}

	current := make(map[string]bool, len(interaction.Member.Roles))
	for _, roleID := range interaction.Member.Roles {
		current[roleID] = true
	}
	changed := 0
	failures := make([]string, 0)
	for _, role := range c.Roles {
		hasRole := current[role.ID]
		wantsRole := selected[role.ID]
		if hasRole == wantsRole {
			continue
		}
		var err error
		if wantsRole {
			err = s.GuildMemberRoleAdd(c.GuildID, interaction.Member.User.ID, role.ID)
		} else {
			err = s.GuildMemberRoleRemove(c.GuildID, interaction.Member.User.ID, role.ID)
		}
		if err != nil {
			failures = append(failures, role.Label)
			continue
		}
		changed++
	}

	reply := fmt.Sprintf("選択を反映しました（変更 %d 件）。", changed)
	if len(failures) > 0 {
		reply = "一部のロールを反映できませんでした: " + strings.Join(failures, "、") + "。権限を確認して、もう一度選択してください。"
	}
	components := c.PickerComponents(selected)
	if _, err := s.InteractionResponseEdit(interaction, &discordgo.WebhookEdit{
		Content:    &reply,
		Components: &components,
	}); err != nil {
		return fmt.Errorf("report role selection result: %w", err)
	}
	return nil
}

func respondEphemeral(s *discordgo.Session, interaction *discordgo.Interaction, content string, components []discordgo.MessageComponent) error {
	return s.InteractionRespond(interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content:    content,
			Flags:      discordgo.MessageFlagsEphemeral,
			Components: components,
		},
	})
}
