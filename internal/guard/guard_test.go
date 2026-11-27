package guard

import (
	"context"
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
