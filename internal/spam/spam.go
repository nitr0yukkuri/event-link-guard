// Package spam detects per-user bursts without network calls or storing raw content.
package spam

import (
	"crypto/sha256"
	"event-link-guard/internal/guard"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	burstWindow = 5 * time.Second
	textWindow  = 20 * time.Second
	urlWindow   = 30 * time.Second
	alertWindow = 30 * time.Second
	maxUsers    = 1024
	maxEvents   = 64
	maxURLs     = 8
)

type Reason string

const (
	Burst      Reason = "message_burst"
	RepeatText Reason = "repeat_text"
	RepeatURL  Reason = "repeat_url"
)

type Result struct {
	Reason           Reason
	Count            int
	Alert            bool
	Duplicate        bool
	CapacityExceeded bool
}
type digest [32]byte
type event struct {
	id      string
	at      time.Time
	text    digest
	hasText bool
	urls    []digest
}
type userState struct {
	events    []event
	lastAlert time.Time
	lastSeen  time.Time
}
type Detector struct {
	mu          sync.Mutex
	users       map[string]*userState
	now         func() time.Time
	lastCleanup time.Time
}

func New() *Detector { return &Detector{users: make(map[string]*userState), now: time.Now} }

// URL equivalence is deliberately conservative: retain path/query, ignore fragment,
// lowercase scheme/host. No redirect resolution or outbound request is performed.
func urlKeys(content string) []digest {
	seen := make(map[digest]bool)
	out := make([]digest, 0, maxURLs)
	for _, raw := range guard.Extract(content) {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		u.RawFragment = ""
		h := sha256.Sum256([]byte(u.String()))
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
		if len(out) == maxURLs {
			break
		}
	}
	return out
}

// Observe accepts new message events only; keys are scoped by the caller to one guild.
// Each distinct message counts at most once within the bounded history.
func (d *Detector) Observe(userID, messageID, content string) Result {
	if userID == "" || messageID == "" {
		return Result{}
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(content), " "))
	e := event{id: messageID, hasText: normalized != "", text: sha256.Sum256([]byte(normalized)), urls: urlKeys(content)}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	e.at = now
	if d.lastCleanup.IsZero() || now.Sub(d.lastCleanup) >= urlWindow {
		for id, u := range d.users {
			if now.Sub(u.lastSeen) >= urlWindow && (u.lastAlert.IsZero() || now.Sub(u.lastAlert) >= alertWindow) {
				delete(d.users, id)
			}
		}
		d.lastCleanup = now
	}
	u := d.users[userID]
	if u == nil {
		if len(d.users) >= maxUsers {
			return Result{CapacityExceeded: true}
		}
		u = &userState{}
		d.users[userID] = u
	}
	// Window semantics: (now-window, now], including the current message.
	first := 0
	for first < len(u.events) && now.Sub(u.events[first].at) >= urlWindow {
		first++
	}
	u.events = append(u.events[:0], u.events[first:]...)
	for _, old := range u.events {
		if old.id == messageID {
			return Result{Duplicate: true}
		}
	}
	u.lastSeen = now
	if len(u.events) >= maxEvents {
		copy(u.events, u.events[1:])
		u.events = u.events[:maxEvents-1]
	}
	u.events = append(u.events, e)
	burst, text := 0, 0
	counts := make(map[digest]int, len(e.urls))
	maxURLCount := 0
	for _, old := range u.events {
		age := now.Sub(old.at)
		if age < burstWindow {
			burst++
		}
		if age < textWindow && e.hasText && old.hasText && old.text == e.text {
			text++
		}
		for _, h := range old.urls {
			for _, target := range e.urls {
				if h == target {
					counts[h]++
					if counts[h] > maxURLCount {
						maxURLCount = counts[h]
					}
					break
				}
			}
		}
	}
	var r Result
	switch {
	case burst >= 6:
		r.Reason = Burst
		r.Count = burst
	case text >= 4:
		r.Reason = RepeatText
		r.Count = text
	case maxURLCount >= 4:
		r.Reason = RepeatURL
		r.Count = maxURLCount
	default:
		return r
	}
	if u.lastAlert.IsZero() || now.Sub(u.lastAlert) >= alertWindow {
		r.Alert = true
		u.lastAlert = now
	}
	return r
}
