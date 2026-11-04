package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func finding() detect.Finding {
	return detect.Finding{
		Principal:  "arn:aws:iam::123456789012:user/<ci>&deploy",
		AccountIDs: []string{"123456789012"},
		SourceIPs:  []string{"203.0.113.50"},
		Regions:    []string{"us-east-1"},
		First:      t0,
		Last:       t0.Add(7 * time.Minute),
		EventCount: 3,
		Confidence: 72,
		Contributors: []detect.Contributor{
			{Kind: "indicator", Name: "quota_increase_request", Weight: 0.2, EventIDs: []string{"1"}},
			{Kind: "indicator", Name: "gpu_instance_launch", Weight: 0.3, EventIDs: []string{"2"}},
			{Kind: "chain", Name: "cryptojacking_chain", Weight: 0.5, EventIDs: []string{"1", "2"}},
		},
	}
}

func decision() *policy.Decision {
	return &policy.Decision{Action: policy.Alert, ProjectedCostUSD: 1344, Reason: policy.ReasonLowConfidence, ForecastWarnings: []string{"pricing <stale>"}}
}

func TestFromFinding(t *testing.T) {
	a := FromFinding(finding(), decision(), &cost.Estimate{PricingVersion: "v1", HourlyCostUSD: 56}, t0.In(time.FixedZone("x", 3600)))
	if a.Schema != Schema || a.Note != Note || a.Confidence != 72 || a.PricingVersion != "v1" || a.HourlyCostUSD != 56 {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if a.GeneratedAt.Location() != time.UTC {
		t.Fatal("generated_at must be UTC")
	}
	if a.Evidence[0].Name != "cryptojacking_chain" || a.Evidence[0].EventCount != 2 || a.Evidence[2].Name != "quota_increase_request" {
		t.Fatalf("evidence not sorted by weight: %+v", a.Evidence)
	}
}

func TestAlertOmitsSensitiveFields(t *testing.T) {
	f := finding()
	a := FromFinding(f, nil, nil, t0)
	for _, format := range []Format{FormatSlack, FormatWebhook} {
		body, err := Render(format, a)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "203.0.113.50") || strings.Contains(string(body), "event_ids") {
			t.Fatalf("%s payload leaks source IPs or event IDs: %s", format, body)
		}
	}
}

func TestRenderWebhook(t *testing.T) {
	body, err := Render(FormatWebhook, FromFinding(finding(), decision(), nil, t0))
	if err != nil {
		t.Fatal(err)
	}
	var got Alert
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || got.Decision == nil || got.Decision.Action != policy.Alert || len(got.Evidence) != 3 {
		t.Fatalf("round trip lost data: %+v", got)
	}
}

func TestRenderSlack(t *testing.T) {
	body, err := Render(FormatSlack, FromFinding(finding(), decision(), &cost.Estimate{PricingVersion: "v1"}, t0))
	if err != nil {
		t.Fatal(err)
	}
	var msg slackPayload
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "72.0% confidence") || len(msg.Blocks) != 3 {
		t.Fatalf("unexpected message: %+v", msg)
	}
	section := msg.Blocks[1].Text.Text
	for _, want := range []string{"&lt;ci&gt;&amp;deploy", "cryptojacking_chain (0.50)", "*Decision:* alert", "$1344.00 (pricing v1)", "pricing &lt;stale&gt;"} {
		if !strings.Contains(section, want) {
			t.Errorf("section missing %q:\n%s", want, section)
		}
	}
	if strings.Contains(section, "<ci>") {
		t.Error("Slack control characters not escaped")
	}
	if msg.Blocks[2].Elements[0].Text != Note {
		t.Error("note missing from context block")
	}
}

func TestRenderSlackWithoutDecision(t *testing.T) {
	f := finding()
	f.AccountIDs, f.Regions, f.Contributors = nil, nil, nil
	body, err := Render(FormatSlack, FromFinding(f, nil, nil, t0))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "Decision") || !strings.Contains(string(body), "*Accounts:* none") {
		t.Fatalf("unexpected payload: %s", body)
	}
}

func TestParseFormatAndRenderUnknown(t *testing.T) {
	if _, err := ParseFormat("email"); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
	if _, err := Render("email", Alert{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

const secretPath = "/services/T000/B000/SECRETTOKEN"

func server(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Sender) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv, Sender{URL: srv.URL + secretPath, Format: FormatSlack, Client: srv.Client(), Backoff: time.Millisecond}
}

func TestSendSuccess(t *testing.T) {
	var gotBody []byte
	var gotType string
	_, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Write([]byte("ok"))
	})
	if err := s.Send(context.Background(), FromFinding(finding(), nil, nil, t0)); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" || !json.Valid(gotBody) {
		t.Fatalf("bad request: type=%q body=%s", gotType, gotBody)
	}
}

func TestSendRetriesTransient(t *testing.T) {
	var calls atomic.Int32
	_, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
	})
	if err := s.Send(context.Background(), Alert{}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("want 3 attempts, got %d", calls.Load())
	}
}

func TestSendGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	_, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})
	s.MaxAttempts = 2
	err := s.Send(context.Background(), Alert{})
	if !errors.Is(err, ErrSend) || !strings.Contains(err.Error(), "HTTP 502") || calls.Load() != 2 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestSendDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	_, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_payload"))
	})
	err := s.Send(context.Background(), Alert{})
	if !errors.Is(err, ErrSend) || !strings.Contains(err.Error(), "HTTP 400: invalid_payload") || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestSendErrorsNeverContainURL(t *testing.T) {
	srv, s := server(t, func(w http.ResponseWriter, r *http.Request) {})
	srv.Close() // connection refused on every attempt
	s.MaxAttempts = 1
	err := s.Send(context.Background(), Alert{})
	if !errors.Is(err, ErrSend) {
		t.Fatalf("want ErrSend, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("error leaks webhook URL: %v", err)
	}
}

func TestSendHonorsContext(t *testing.T) {
	_, s := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	s.Backoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.Send(ctx, Alert{})
	if !errors.Is(err, ErrSend) || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
}

func TestValidate(t *testing.T) {
	for name, s := range map[string]Sender{
		"plain http":       {URL: "http://hooks.example.com/x", Format: FormatSlack},
		"relative":         {URL: "/x", Format: FormatSlack},
		"garbage":          {URL: "://", Format: FormatSlack},
		"empty":            {URL: "", Format: FormatWebhook},
		"bad format":       {URL: "https://hooks.example.com/x", Format: "email"},
		"negative attempt": {URL: "https://hooks.example.com/x", Format: FormatSlack, MaxAttempts: -1},
	} {
		t.Run(name, func(t *testing.T) {
			err := s.Validate()
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("want ErrConfig, got %v", err)
			}
			if s.URL != "" && strings.Contains(err.Error(), s.URL) {
				t.Fatalf("error leaks URL: %v", err)
			}
		})
	}
	if err := (Sender{URL: "https://hooks.example.com/x", Format: FormatWebhook}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSendRejectsInvalidConfigWithoutRequest(t *testing.T) {
	if err := (Sender{URL: "http://insecure.example.com", Format: FormatSlack}).Send(context.Background(), Alert{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestSlackTitleShowsUpdate(t *testing.T) {
	for update, prefix := range map[string]string{"": "Cloud Abuse", "escalated": "Escalated: ", "reminder": "Reminder: "} {
		a := FromFinding(finding(), nil, nil, t0)
		a.Update = update
		body, err := Render(FormatSlack, a)
		if err != nil {
			t.Fatal(err)
		}
		var msg slackPayload
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(msg.Text, prefix) {
			t.Errorf("update %q: title %q, want prefix %q", update, msg.Text, prefix)
		}
	}
}

func TestAlertIncidentAndEvidence(t *testing.T) {
	a := FromFinding(finding(), nil, nil, t0)
	if a.IncidentID != finding().IncidentID() || !strings.HasPrefix(a.IncidentID, "inc_") {
		t.Fatalf("incident ID not set: %q", a.IncidentID)
	}
	body, _ := Render(FormatSlack, a)
	if strings.Contains(string(body), "Evidence record") {
		t.Fatal("no evidence line expected without a hash")
	}
	a.EvidenceHash = strings.Repeat("ab", 32)
	body, _ = Render(FormatSlack, a)
	var msg slackPayload
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Blocks[1].Text.Text, a.IncidentID) || len(msg.Blocks[2].Elements) != 2 ||
		msg.Blocks[2].Elements[1].Text != "Evidence record "+strings.Repeat("ab", 8) {
		t.Fatalf("unexpected message: %+v", msg)
	}
	hook, _ := Render(FormatWebhook, a)
	if !strings.Contains(string(hook), `"evidence_hash":"`+a.EvidenceHash+`"`) {
		t.Fatalf("webhook payload must carry the full hash: %s", hook)
	}
}
