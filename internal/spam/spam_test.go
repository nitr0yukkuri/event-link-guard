package spam

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func clocked() (*Detector, *time.Time) {
	d := New()
	n := time.Unix(1000, 0)
	d.now = func() time.Time { return n }
	return d, &n
}
func TestBurstAndAlert(t *testing.T) {
	d, n := clocked()
	for i := 0; i < 8; i++ {
		r := d.Observe("u", fmt.Sprint(i), fmt.Sprint(i))
		if i < 5 && r.Reason != "" {
			t.Fatal(r)
		}
		if i >= 5 && (r.Reason != Burst || r.Alert != (i == 5)) {
			t.Fatal(r)
		}
	}
	*n = n.Add(30 * time.Second)
	if r := d.Observe("u", "fresh", "new"); r.Reason != "" {
		t.Fatal(r)
	}
}
func TestBoundary(t *testing.T) {
	d, n := clocked()
	for i := 0; i < 5; i++ {
		d.Observe("u", fmt.Sprint(i), fmt.Sprint(i))
	}
	*n = n.Add(5 * time.Second)
	if r := d.Observe("u", "6", "6"); r.Reason != "" {
		t.Fatal(r)
	}
}
func TestRepeatText(t *testing.T) {
	d, n := clocked()
	for i, c := range []string{"Hello WORLD", "hello world", "hello\tworld", " HELLO world  "} {
		r := d.Observe("u", fmt.Sprint(i), c)
		if i == 3 && r.Reason != RepeatText {
			t.Fatal(r)
		}
		if i < 3 && r.Reason != "" {
			t.Fatal(r)
		}
		*n = n.Add(4 * time.Second)
	}
}
func TestRepeatURL(t *testing.T) {
	d, n := clocked()
	for i, c := range []string{"https://example.com/event#1", "new https://EXAMPLE.com/event", "other https://example.com/event#2", "last https://example.com/event"} {
		r := d.Observe("u", fmt.Sprint(i), c)
		if i == 3 && r.Reason != RepeatURL {
			t.Fatal(r)
		}
		if i < 3 && r.Reason != "" {
			t.Fatal(r)
		}
		*n = n.Add(6 * time.Second)
	}
}
func TestDifferentUsersAndURLs(t *testing.T) {
	d, n := clocked()
	for i := 0; i < 10; i++ {
		if r := d.Observe(fmt.Sprint(i), fmt.Sprint(i), "https://example.com/event"); r.Reason != "" {
			t.Fatal(r)
		}
	}
	for i := 0; i < 8; i++ {
		if r := d.Observe("other", fmt.Sprint(i), fmt.Sprintf("https://example.com/event/%d", i)); r.Reason != "" {
			t.Fatal(r)
		}
		*n = n.Add(4 * time.Second)
	}
}
func TestDedupAndEmpty(t *testing.T) {
	d, _ := clocked()
	for i := 0; i < 10; i++ {
		r := d.Observe("u", "same", "")
		if r.Duplicate != (i > 0) || r.Reason != "" {
			t.Fatal(r)
		}
	}
	for i := 0; i < 5; i++ {
		r := d.Observe("u", fmt.Sprint(i), "")
		if i == 4 && r.Reason != Burst {
			t.Fatal(r)
		}
	}
}
func TestURLCountsOncePerMessage(t *testing.T) {
	d, _ := clocked()
	r := d.Observe("u", "1", "https://example.com/a https://example.com/a#b https://example.com/a#c https://example.com/a#d")
	if r.Reason != "" {
		t.Fatal(r)
	}
}
func TestCapacityAndExpiry(t *testing.T) {
	d, n := clocked()
	for i := 0; i < maxUsers; i++ {
		d.Observe(fmt.Sprint(i), "m", "x")
	}
	if !d.Observe("extra", "m", "x").CapacityExceeded {
		t.Fatal("capacity")
	}
	*n = n.Add(urlWindow)
	if d.Observe("extra", "m", "x").CapacityExceeded {
		t.Fatal("expiry")
	}
}
func TestConcurrent(t *testing.T) {
	d := New()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); d.Observe("u", fmt.Sprint(i), "x") }(i)
	}
	wg.Wait()
	if len(d.users["u"].events) > maxEvents {
		t.Fatal("unbounded")
	}
}
