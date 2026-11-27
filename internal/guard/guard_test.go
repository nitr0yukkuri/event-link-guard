package guard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type fake Verdict

func (f fake) Check(context.Context, string) Verdict { return Verdict(f) }
func TestInspect(t *testing.T) {
	for _, c := range []struct {
		input          string
		provider, want Verdict
		count          int
	}{
		{"[event](https://example.com/event) <https://example.com/event>", NoMatch, NoMatch, 1},
		{"hello", Threat, NoMatch, 0},
		{"https://example.com/event", Threat, Threat, 1},
		{"https://example.com/event", Unknown, Unknown, 1},
		{"https://example.com/event?secret=x", Threat, Unknown, 1},
		{"https://user:pass@example.com/", Threat, Unknown, 1},
		{"https://127.0.0.1/", Threat, Unknown, 1},
		{"https://example.com/event https://forms.gle/foo", Threat, Threat, 2},
		{"https://example.com/event https://forms.gle/foo", NoMatch, Unknown, 2},
	} {
		r := Inspect(context.Background(), fake(c.provider), c.input)
		if r.Verdict != c.want || r.Count != c.count {
			t.Errorf("%q: got %+v want %s/%d", c.input, r, c.want, c.count)
		}
	}
}
func TestGoogle(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		want       Verdict
	}{
		{"no match", `{"cacheDuration":"300s"}`, 200, NoMatch},
		{"match expression", `{"threats":[{"url":"https://example.com/","threatTypes":["SOCIAL_ENGINEERING"]}],"cacheDuration":"300s"}`, 200, Threat},
		{"invalid", `{}`, 200, Unknown}, {"rate limited", `{}`, 429, Unknown},
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
			if tc.want != Unknown && calls.Load() != 1 {
				t.Error("cache not used")
			}
		})
	}
}
