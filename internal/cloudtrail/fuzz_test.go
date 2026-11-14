package cloudtrail

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReplay checks that no log file, however malformed, can panic the
// parser or the indicator rules.
func FuzzReplay(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	for _, p := range paths {
		if raw, err := os.ReadFile(p); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(`{"Records":[{"eventTime":"2026-11-04T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","eventID":"1","requestParameters":{"policyArn":7}}]}`))
	f.Add([]byte("\x1f\x8b\x08\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		events, err := Replay(bytes.NewReader(data))
		if err != nil {
			return
		}
		Summarize(events)
		for i := 1; i < len(events); i++ {
			if events[i].Time.Before(events[i-1].Time) {
				t.Fatal("events not sorted")
			}
		}
	})
}
