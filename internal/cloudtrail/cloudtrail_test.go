package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

type replayOutput struct {
	Events  []Event `json:"events"`
	Summary Summary `json:"summary"`
}

// TestReplayGolden replays every testdata/*.json log and compares the
// normalized output with its .golden file. Run with -update to regenerate.
func TestReplayGolden(t *testing.T) {
	logs, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(logs) == 0 {
		t.Fatalf("no replay fixtures found: %v", err)
	}
	for _, path := range logs {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			events, err := Replay(f)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(replayOutput{events, Summarize(events)}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := strings.TrimSuffix(path, ".json") + ".golden"
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/cloudtrail -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("replay output differs from %s; run with -update if the change is intended.\ngot:\n%s", golden, got)
			}
		})
	}
}

// The incident fixture must surface every indicator, and must not leak the raw key ID.
func TestIncidentFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := Replay(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(events)
	for _, ind := range []Indicator{GPUInstanceLaunch, BulkInstanceLaunch, QuotaIncreaseRequest, MonitoringTampering,
		BedrockLoggingDisabled, BedrockModelAccessChange, CredentialCreation, AccessDenied, RootActivity} {
		if s.ByIndicator[ind] == 0 {
			t.Errorf("indicator %s not found in incident fixture", ind)
		}
	}
	for i := 1; i < len(events); i++ {
		if events[i].Time.Before(events[i-1].Time) {
			t.Fatalf("events not sorted at %d", i)
		}
	}
	out, _ := json.Marshal(events)
	if bytes.Contains(out, []byte("AKIAIOSFODNN7EXAMPLE")) || bytes.Contains(out, []byte("sensitiveDataRemoved")) {
		t.Fatal("normalized events leak raw key IDs or request parameters")
	}
}

func TestParseGzip(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(raw)
	zw.Close()
	plain, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, gz) {
		t.Fatal("gzip and plain parse differ")
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	ok := `"eventTime":"2026-11-04T10:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"X","eventID":"1"`
	for name, doc := range map[string]string{
		"not json":          `nope`,
		"no records":        `{}`,
		"trailing data":     `{"Records":[]} {}`,
		"missing time":      `{"Records":[{"eventSource":"s","eventName":"n","eventID":"1"}]}`,
		"missing source":    `{"Records":[{"eventTime":"2026-11-04T10:00:00Z","eventName":"n","eventID":"1"}]}`,
		"missing name":      `{"Records":[{"eventTime":"2026-11-04T10:00:00Z","eventSource":"s","eventID":"1"}]}`,
		"missing id":        `{"Records":[{"eventTime":"2026-11-04T10:00:00Z","eventSource":"s","eventName":"n"}]}`,
		"bad time":          `{"Records":[{` + strings.Replace(ok, "2026-11-04T10:00:00Z", "yesterday", 1) + `}]}`,
		"corrupt gzip body": "\x1f\x8b garbage",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
	if recs, err := Parse(strings.NewReader(`{"Records":[{` + ok + `,"newField":{"a":1}}]}`)); err != nil || len(recs) != 1 {
		t.Fatalf("unknown fields must be tolerated: %v", err)
	}
	if recs, err := Parse(strings.NewReader(`{"Records":[]}`)); err != nil || len(recs) != 0 {
		t.Fatalf("empty log must parse: %v", err)
	}
}

func TestParseSizeLimit(t *testing.T) {
	old := maxDecodedBytes
	maxDecodedBytes = 1024
	t.Cleanup(func() { maxDecodedBytes = old })
	// A valid prefix followed by more data than the cap allows.
	r := io.MultiReader(strings.NewReader(`{"Records":[`), strings.NewReader(strings.Repeat(" ", 2048)))
	if _, err := Parse(r); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

func TestMaskAccessKeyID(t *testing.T) {
	for in, want := range map[string]string{
		"AKIAIOSFODNN7EXAMPLE": "AKIA************MPLE",
		"short":                "*****",
		"":                     "",
	} {
		if got := MaskAccessKeyID(in); got != want {
			t.Errorf("MaskAccessKeyID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAccelerated(t *testing.T) {
	for typ, want := range map[string]bool{
		"p4d.24xlarge": true, "p5.48xlarge": true, "g5.xlarge": true, "g4dn.12xlarge": true,
		"inf2.48xlarge": true, "trn1.32xlarge": true, "dl1.24xlarge": true,
		"t3.micro": false, "m6g.large": false, "c7gn.16xlarge": false, "": false, "gpu": false,
	} {
		if got := accelerated(typ); got != want {
			t.Errorf("accelerated(%q) = %v, want %v", typ, got, want)
		}
	}
}

func baseRecord() Record {
	return Record{
		EventTime:   time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
		EventSource: "ec2.amazonaws.com",
		EventName:   "RunInstances",
		EventID:     "e1",
		UserIdentity: UserIdentity{
			Type:      "IAMUser",
			AccountID: "123456789012",
		},
	}
}

func TestNormalizeEdgeCases(t *testing.T) {
	t.Run("malformed RunInstances params still reported", func(t *testing.T) {
		rec := baseRecord()
		rec.RequestParameters = json.RawMessage(`"not an object"`)
		ev := Normalize(rec)
		if ev.Action != "RunInstances" || ev.InstanceType != "" || len(ev.Indicators) != 0 {
			t.Fatalf("unexpected event: %+v", ev)
		}
	})
	t.Run("minCount above maxCount counts minCount", func(t *testing.T) {
		rec := baseRecord()
		rec.RequestParameters = json.RawMessage(`{"instanceType":"t3.micro","instancesSet":{"items":[{"minCount":12,"maxCount":1},{"minCount":-3,"maxCount":-3}]}}`)
		ev := Normalize(rec)
		if ev.InstanceCount != 12 || len(ev.Indicators) != 1 || ev.Indicators[0] != BulkInstanceLaunch {
			t.Fatalf("unexpected event: %+v", ev)
		}
	})
	t.Run("account falls back to identity", func(t *testing.T) {
		if ev := Normalize(baseRecord()); ev.AccountID != "123456789012" {
			t.Fatalf("got account %q", ev.AccountID)
		}
	})
	t.Run("root via AWS service is not root activity", func(t *testing.T) {
		rec := baseRecord()
		rec.EventSource, rec.EventName = "s3.amazonaws.com", "GetObject"
		rec.UserIdentity = UserIdentity{Type: "Root", InvokedBy: "cloudfront.amazonaws.com"}
		if ev := Normalize(rec); len(ev.Indicators) != 0 {
			t.Fatalf("unexpected indicators: %v", ev.Indicators)
		}
	})
	t.Run("user agent truncated", func(t *testing.T) {
		rec := baseRecord()
		rec.UserAgent = strings.Repeat("a", 1000)
		if ev := Normalize(rec); len(ev.UserAgent) != maxUserAgentLen {
			t.Fatalf("user agent length %d", len(ev.UserAgent))
		}
	})
	t.Run("time normalized to UTC", func(t *testing.T) {
		rec := baseRecord()
		rec.EventTime = rec.EventTime.In(time.FixedZone("x", 3600))
		if ev := Normalize(rec); ev.Time.Location() != time.UTC {
			t.Fatalf("time not UTC: %v", ev.Time)
		}
	})
	t.Run("indicators deduplicated", func(t *testing.T) {
		rec := baseRecord()
		rec.EventSource, rec.EventName = "iam.amazonaws.com", "CreateAccessKey"
		rec.ErrorCode = "AccessDenied"
		ev := Normalize(rec)
		if !reflect.DeepEqual(ev.Indicators, []Indicator{CredentialCreation, AccessDenied}) {
			t.Fatalf("got %v", ev.Indicators)
		}
	})
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(nil)
	if s.Events != 0 || !s.First.IsZero() || len(s.ByIndicator) != 0 {
		t.Fatalf("unexpected summary: %+v", s)
	}
}
