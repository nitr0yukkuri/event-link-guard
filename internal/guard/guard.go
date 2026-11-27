package guard

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

type Verdict string

const (
	NoMatch Verdict = "NO_MATCH"
	Threat  Verdict = "THREAT_MATCH"
	Unknown Verdict = "UNKNOWN"
)

type Checker interface {
	Check(context.Context, string) Verdict
}
type Result struct {
	Verdict Verdict
	Count   int
	Reason  string
}

// Extract covers explicit HTTP(S) links, including Markdown link targets.
// Deliberately does not claim to reproduce Discord's full link renderer.
var links = regexp.MustCompile(`(?i)https?://[^\s<>"\x60]+`)

func Extract(content string) []string {
	found := links.FindAllString(content, -1)
	out := make([]string, 0, len(found))
	seen := map[string]bool{}
	for _, raw := range found {
		raw = strings.TrimRight(raw, "、。！？.,!;]}")
		for strings.HasSuffix(raw, ")") && strings.Count(raw, ")") > strings.Count(raw, "(") {
			raw = strings.TrimSuffix(raw, ")")
		}
		if !seen[raw] {
			seen[raw] = true
			out = append(out, raw)
		}
	}
	return out
}

// PublicURL is intentionally conservative: never submit credentials, query strings,
// fragments or common private hosts to a service which may share submitted URLs.
// This is a privacy policy, not a general safety guarantee.
func PublicURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || len(raw) > 2048 {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".onion") || strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".invalid") || strings.HasSuffix(host, ".example") || strings.HasSuffix(host, ".home") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".corp") {
		return "", false
	}
	// Avoid IP literals, unusual hosts and alternate numeric IP spellings.
	if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z][a-z0-9-]*$`).MatchString(host) || strings.Contains(host, "..") {
		return "", false
	}
	// Do not send known private invitation/document path patterns by default.
	lower := strings.ToLower(u.EscapedPath())
	for _, p := range []string{"/invite/", "/invites/", "/token/", "/reset/", "/oauth/", "/auth/", "/share/", "/private/"} {
		if strings.Contains(lower, p) {
			return "", false
		}
	}
	switch host {
	case "discord.gg", "forms.gle", "docs.google.com", "drive.google.com", "bit.ly", "t.co", "tinyurl.com", "luma.com", "lu.ma":
		return "", false
	}
	return raw, true
}
func Inspect(ctx context.Context, c Checker, content string) Result {
	urls := Extract(content)
	r := Result{Verdict: NoMatch, Count: len(urls)}
	if len(urls) > 8 {
		return Result{Unknown, len(urls), "too_many_urls"}
	}
	for _, raw := range urls {
		u, ok := PublicURL(raw)
		if !ok {
			r.Verdict = Unknown
			r.Reason = "privacy_or_unsupported_url"
			continue
		}
		switch c.Check(ctx, u) {
		case Threat:
			return Result{Threat, len(urls), "google_threat_match"}
		case NoMatch:
		default:
			r.Verdict = Unknown
			r.Reason = "provider_unavailable"
		}
	}
	return r
}
