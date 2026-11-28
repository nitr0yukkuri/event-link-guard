# Event Link Guard

A small Discord toolkit written in Go for event-sharing communities, with a URL and spam guard plus a separate ordered role picker.

**v0.2 — experimental MVP. Monitor-only by default. Not yet validated against a live Discord server or Google API.**

## Features

- Inspect explicit HTTP(S) links in new and edited messages with Google Safe Browsing v5.
- No direct requests to posted destinations or redirect resolution.
- Per-user sliding-window spam detection across configured channels.
- Independent bounded queues for URL inspection and spam actions.
- Optional message deletion, private moderation logs, no automatic bans, timeouts or reaction monitoring.
- Standalone ordered multi-select role panel that changes only configured, permissionless roles.

| Spam rule | Initial threshold |
| --- | --- |
| Message burst | 6 messages within 5 seconds |
| Repeated text | 4 normalized identical messages within 20 seconds |
| Repeated URL | 4 distinct messages containing the same URL within 30 seconds |

## Ordered role picker

The standalone \`cmd/rolepicker\` process adds an ordered, multi-select role panel for event communities. Members open a private selection menu from one public button. Option order follows the JSON file, and existing selections appear preselected when the menu opens.

It only adds or removes the roles listed in \`ROLE_PICKER_ROLES_JSON\`. Other member roles, Carl-bot messages, and existing reaction roles are not modified. To keep self-service safe, startup refuses configured roles that have permissions, are integration-managed, are missing or duplicated by name, or sit at or above the bot's highest role. The bot also needs Manage Roles. It does not create server roles.

1. Create a separate Discord application/bot for this process. Invite it with the \`bot\` and \`applications.commands\` scopes. Grant only View Channel, Send Messages, Read Message History, and Manage Roles for the role channel; do not grant Administrator. Enable no privileged gateway intents.
2. Create the server roles first. Configure their exact names in \`rolepicker.roles.example.json\`, then copy that file and set \`ROLE_PICKER_ROLES_JSON\` to its contents. The JSON order controls the panel and menu order. Change the sample list to match the roles that actually exist in the server.
3. Move the bot's highest role above every configured self-selectable role. Keep those roles permissionless. Set \`ROLE_PICKER_TOKEN\`, \`ROLE_PICKER_GUILD_ID\`, and \`ROLE_PICKER_CHANNEL_ID\` in the process environment. Optionally set \`ROLE_PICKER_PANEL_MESSAGE_ID\` to pin updates to a specific panel message.
4. Start the bot with \`go run ./cmd/rolepicker\`. A server administrator can then run \`/role-panel\`; it creates the panel or updates this bot's existing panel in the configured channel. Without a message ID, it searches the latest 100 messages in that channel for its own panel.

PowerShell example:

\`\`\`powershell
$env:ROLE_PICKER_TOKEN = 'YOUR_BOT_TOKEN'
$env:ROLE_PICKER_GUILD_ID = 'YOUR_SERVER_ID'
$env:ROLE_PICKER_CHANNEL_ID = 'ROLE_CHANNEL_ID'
$env:ROLE_PICKER_ROLES_JSON = Get-Content .\\rolepicker.roles.example.json -Raw
go run ./cmd/rolepicker
\`\`\`

This process is separate from \`cmd/linkguard\`: it does not need the Google API key, Message Content intent, or URL-inspection consent setting. The role picker stores no member data; Discord remains the source of each member's role state. Run it continuously for the interaction buttons to remain available.

## Setup

1. Install a currently supported Go version (module requires Go 1.23+).
2. Create a bot at https://discord.com/developers/applications and enable Message Content Intent.
3. Grant View Channel and Read Message History for monitored channels; grant Manage Messages only if deletion is enabled. Grant View Channel and Send Messages for the private log channel. Administrator is not required.
4. Enable Google Safe Browsing API and create an API-restricted key.
5. Read the privacy notice below and inform community members before enabling URL inspection.

PowerShell:

```powershell
$env:DISCORD_TOKEN='YOUR_BOT_TOKEN'
$env:GOOGLE_API_KEY='YOUR_API_KEY'
$env:DISCORD_GUILD_ID='YOUR_SERVER_ID'
$env:DISCORD_CHANNEL_IDS='EVENT_CHANNEL_ID'
$env:DISCORD_LOG_CHANNEL_ID='ADMIN_LOG_CHANNEL_ID'
$env:ACK_URL_SHARING='true'
$env:ENFORCE='false'
$env:SPAM_ENFORCE='false'
go mod tidy
go test -race ./...
go run ./cmd/linkguard
```

Channel IDs can be comma separated. Optional SPAM_CHANNEL_IDS defaults to DISCORD_CHANNEL_IDS. The log channel must not be monitored. The app does not load .env automatically. Never commit credentials. A continuously running host is needed.

## Privacy and limitations

This prototype sends eligible full URLs to Google Safe Browsing, which may use and share submitted information. It is for noncommercial use only. Do not monitor private channels. Notify members explicitly before setting ACK_URL_SHARING=true. Query strings, fragments, credentials, IP literals, selected private/share links and shorteners are skipped, but secrets in paths may still be transmitted. Never post confidential or restricted URLs in monitored channels. A future hash-based implementation is planned.

NO_MATCH means no known threat was returned, not that a link is safe. UNKNOWN retains the message and notifies moderators. THREAT_MATCH only deletes when ENFORCE=true; the message is fetched again before deletion, though edit/delete races remain possible.

Spam detection hashes normalized text and URL keys in memory; hashes are not an anonymity guarantee. History is bounded (1024 users, 64 messages per user, 8 URL keys per message). Alerts are throttled per user for 30 seconds. SPAM_ENFORCE=true deletes only the triggering message. Edits do not count as new messages. Bots and webhooks are excluded. Attachments and stickers count as messages, not reactions.

Explicit HTTP(S) extraction does not reproduce Discord's renderer. Bare domains, Unicode hosts, shortener targets, some Markdown, coordinated raids and unconfigured channels/threads may be missed. Bounded queues, outages, REST rate limits and restarts may cause detection or action gaps. Use Discord AutoMod and slow mode as complementary controls. No automatic ban or timeout. Start in monitor-only mode and tune thresholds before enabling deletion.

Example member notice (Japanese):

> 公開イベント共有チャンネルでは、フィッシング等の対策として投稿された公開URLをGoogle Safe Browsingに照会する場合があります。Googleは送信情報を利用し、第三者と共有する場合があります。個人情報・限定公開リンク・認証トークンを含むURLは投稿しないでください。検知の正確性・網羅性は保証されません。危険な可能性のあるリンクは管理者確認や削除の対象になる場合があります。Advisory provided by Google: https://developers.google.com/safe-browsing/v4/advisory

## Verification

- `go vet ./...` and `go build ./cmd/linkguard ./cmd/rolepicker` pass locally.
- `go test ./...` cannot complete the existing `internal/guard` HTTP tests in this Windows sandbox: `httptest` loopback connections are denied by the environment. The spam detector tests pass. Run the suite in CI or an environment that permits local TCP connections.
- The role picker has not yet connected to a live Discord server. Before production: live Gateway integration, role permission review, URL fuzz tests, dependency security review, load tests, privacy-preserving threat lookup and alert aggregation.

## References

- https://developers.google.com/safe-browsing/reference/rest/v5/urls/search
- https://developers.google.com/safe-browsing/reference/Appropriate.Usage
- https://developers.google.com/safe-browsing/terms
- https://discord.com/developers/docs/intro

## License

MIT

