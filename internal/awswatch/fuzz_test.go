package awswatch

import (
	"context"
	"testing"
	"time"
)

func FuzzFetchAndBuffer(f *testing.F) {
	f.Add([]byte(`{"Events":[{"EventId":"e1","CloudTrailEvent":"{\"eventID\":\"e1\",\"eventTime\":\"2026-11-09T10:00:00Z\"}"}]}`))
	f.Add([]byte(`{"Events":[],"NextToken":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		now := time.Now().UTC()
		run := func(context.Context, ...string) ([]byte, error) { return data, nil }
		payload, _, err := Fetch(context.Background(), run, "us-east-1", now.Add(-time.Minute), now)
		if err != nil {
			return
		}
		b, _ := NewBuffer(time.Hour, 10)
		if _, err := b.Add(payload); err != nil {
			return
		}
		if _, n, err := b.Payload(now); err != nil || n > 10 {
			t.Fatalf("payload: %d %v", n, err)
		}
	})
}
