package awswatch

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var b0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func envelope(events ...string) []byte {
	return []byte(`{"Records":[` + strings.Join(events, ",") + `]}`)
}

func event(id string, at time.Time) string {
	return fmt.Sprintf(`{"eventID":%q,"eventTime":%q,"eventName":"X"}`, id, at.Format(time.RFC3339))
}

func TestBufferMergesAndExpires(t *testing.T) {
	b, err := NewBuffer(time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := b.Add(envelope(event("a", b0), event("b", b0.Add(10*time.Minute)))); err != nil || n != 2 {
		t.Fatalf("first add: %d %v", n, err)
	}
	// An overlapping poll returns "b" again plus a new event.
	if n, err := b.Add(envelope(event("b", b0.Add(10*time.Minute)), event("c", b0.Add(50*time.Minute)))); err != nil || n != 1 {
		t.Fatalf("overlap add: %d %v", n, err)
	}
	payload, n, err := b.Payload(b0.Add(55 * time.Minute))
	if err != nil || n != 3 || strings.Index(string(payload), `"a"`) > strings.Index(string(payload), `"c"`) {
		t.Fatalf("payload: %d %v %s", n, err, payload)
	}
	// 65 minutes in, "a" (at +0) is past the one-hour horizon.
	payload, n, _ = b.Payload(b0.Add(65 * time.Minute))
	if n != 2 || strings.Contains(string(payload), `"a"`) {
		t.Fatalf("expiry: %d %s", n, payload)
	}
	if _, n, _ = b.Payload(b0.Add(3 * time.Hour)); n != 0 {
		t.Fatalf("all events must expire: %d", n)
	}
}

func TestBufferKeepsNewestWhenFull(t *testing.T) {
	b, _ := NewBuffer(time.Hour, 2)
	b.Add(envelope(event("old", b0), event("mid", b0.Add(time.Minute)), event("new", b0.Add(2*time.Minute))))
	payload, n, _ := b.Payload(b0.Add(3 * time.Minute))
	if n != 2 || strings.Contains(string(payload), `"old"`) {
		t.Fatalf("cap: %d %s", n, payload)
	}
	if n, _ := b.Add(envelope(event("old", b0))); n != 1 {
		t.Fatal("an evicted event may be re-added")
	}
}

func TestBufferRejectsBadInput(t *testing.T) {
	if _, err := NewBuffer(0, 1); err == nil {
		t.Fatal("zero horizon accepted")
	}
	if _, err := NewBuffer(time.Hour, 0); err == nil {
		t.Fatal("zero size accepted")
	}
	b, _ := NewBuffer(time.Hour, 10)
	for _, bad := range []string{`nope`, `{"Records":[{"eventTime":"2026-11-13T10:00:00Z"}]}`, `{"Records":[{"eventID":"x"}]}`, `{"Records":["x"]}`} {
		if _, err := b.Add([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
