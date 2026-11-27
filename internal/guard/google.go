package guard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const endpoint = "https://safebrowsing.googleapis.com/v5/urls:search"

type entry struct {
	verdict          Verdict
	expires, checked time.Time
}
type Google struct {
	key, endpoint string
	client        *http.Client
	mu            sync.Mutex
	cache         map[[32]byte]entry
}

func NewGoogle(key string) *Google {
	return &Google{key: key, endpoint: endpoint, client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cache: make(map[[32]byte]entry)}
}
func (g *Google) Check(ctx context.Context, raw string) Verdict {
	if g.key == "" {
		return Unknown
	}
	key := sha256.Sum256([]byte(raw))
	now := time.Now()
	g.mu.Lock()
	e, ok := g.cache[key]
	g.mu.Unlock()
	if ok && now.Before(e.expires) {
		if e.verdict == Threat && now.Sub(e.checked) >= 30*time.Minute {
			return Unknown
		}
		return e.verdict
	}
	dest, err := url.Parse(g.endpoint)
	if err != nil {
		return Unknown
	}
	q := dest.Query()
	q.Set("key", g.key)
	q.Set("urls", raw)
	dest.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.String(), nil)
	if err != nil {
		return Unknown
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return Unknown
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Unknown
	}
	var data struct {
		Threats []struct {
			URL   string   `json:"url"`
			Types []string `json:"threatTypes"`
		} `json:"threats"`
		CacheDuration string `json:"cacheDuration"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if dec.Decode(&data) != nil {
		return Unknown
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return Unknown
	}
	ttl, err := time.ParseDuration(data.CacheDuration)
	if err != nil || ttl < 0 {
		return Unknown
	}
	v := NoMatch
	for _, t := range data.Threats {
		if t.URL == "" || len(t.Types) == 0 {
			return Unknown
		}
		v = Threat
	}
	now = time.Now()
	g.mu.Lock()
	for k, v := range g.cache {
		if !now.Before(v.expires) {
			delete(g.cache, k)
		}
	}
	if len(g.cache) >= 4096 {
		g.mu.Unlock()
		return Unknown
	}
	g.cache[key] = entry{v, now.Add(ttl), now}
	g.mu.Unlock()
	return v
}
