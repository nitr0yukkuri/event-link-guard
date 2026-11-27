package safebrowsing

import (
 "context"
 "event-link-guard/internal/guard"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
)

func TestGoogle(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		want       guard.Verdict
	}{
		{"no match", `{"cacheDuration":"300s"}`, 200, guard.NoMatch},
		{"match expression", `{"threats":[{"url":"https://example.com/","threatTypes":["SOCIAL_ENGINEERING"]}],"cacheDuration":"300s"}`, 200, guard.Threat},
		{"invalid", `{}`, 200, guard.Unknown}, {"rate limited", `{}`, 429, guard.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Query().Get("urls") != "https://example.com/event" {
					t.Error("wrong url")
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			g := NewGoogle("test")
			g.endpoint = s.URL
			for i := 0; i < 2; i++ {
				if v := g.Check(context.Background(), "https://example.com/event"); v != tc.want {
					t.Fatalf("got %s want %s", v, tc.want)
				}
			}
			if tc.want != guard.Unknown && calls.Load() != 1 {
				t.Error("cache not used")
			}
		})
	}
}
