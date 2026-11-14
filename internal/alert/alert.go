// Package alert turns scored findings into notifications and delivers them
// to Slack incoming webhooks or generic JSON webhooks.
//
// Alerts are informational: sending one never triggers a response action.
// Content is deliberately minimal because it leaves the trust boundary for a
// third-party service: source IPs, user agents and access key IDs are not
// included. Webhook URLs are treated as secrets and never appear in errors.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/host"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

// Schema identifies the generic webhook payload version.
const Schema = "cad.alert.v1"

// Note is attached to every alert so recipients know nothing was changed.
const Note = "Informational alert. No automated action has been taken; any containment requires operator approval."

var (
	// ErrConfig is wrapped by sender configuration errors.
	ErrConfig = errors.New("invalid alert configuration")
	// ErrSend is wrapped by delivery failures.
	ErrSend = errors.New("alert delivery failed")
)

// Format selects the payload shape.
type Format string

const (
	FormatSlack   Format = "slack"
	FormatWebhook Format = "webhook"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatSlack, FormatWebhook:
		return f, nil
	}
	return "", fmt.Errorf("%w: unknown format %q (want %q or %q)", ErrConfig, s, FormatSlack, FormatWebhook)
}

// Evidence summarizes one contributor without its event IDs.
type Evidence struct {
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	Weight     float64 `json:"weight"`
	EventCount int     `json:"event_count"`
}

// Alert is the minimal, recipient-safe view of a finding.
type Alert struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	// Source is "cloudtrail" or "host".
	Source     string `json:"source"`
	IncidentID string `json:"incident_id"`
	// EvidenceHash is the hash of the evidence-log record behind this alert,
	// when an evidence log is kept. Keeping it outside the log lets a later
	// rewrite of the whole log be detected.
	EvidenceHash string `json:"evidence_hash,omitempty"`
	Principal    string `json:"principal"`
	// Linked are identities the principal created whose activity is included.
	Linked         []string         `json:"linked_principals,omitempty"`
	AccountIDs     []string         `json:"account_ids,omitempty"`
	Regions        []string         `json:"regions,omitempty"`
	First          time.Time        `json:"first_event_time"`
	Last           time.Time        `json:"last_event_time"`
	Confidence     float64          `json:"confidence"`
	Evidence       []Evidence       `json:"evidence"`
	Decision       *policy.Decision `json:"decision,omitempty"`
	PricingVersion string           `json:"pricing_version,omitempty"`
	HourlyCostUSD  float64          `json:"hourly_cost_usd,omitempty"`
	// Update is "escalated" or "reminder" when an earlier alert for the same
	// incident was already delivered, and empty for a first alert.
	Update string `json:"update,omitempty"`
	Note   string `json:"note"`
}

// FromFinding builds an alert. decision and estimate may be nil.
func FromFinding(f detect.Finding, decision *policy.Decision, estimate *cost.Estimate, now time.Time) Alert {
	a := Alert{
		Schema:      Schema,
		GeneratedAt: now.UTC(),
		Source:      SourceCloudTrail,
		IncidentID:  f.IncidentID(),
		Principal:   f.Principal,
		Linked:      f.LinkedPrincipals,
		AccountIDs:  f.AccountIDs,
		Regions:     f.Regions,
		First:       f.First,
		Last:        f.Last,
		Confidence:  f.Confidence,
		Evidence:    make([]Evidence, 0, len(f.Contributors)),
		Decision:    decision,
		Note:        Note,
	}
	for _, c := range f.Contributors {
		a.Evidence = append(a.Evidence, Evidence{Kind: c.Kind, Name: c.Name, Weight: c.Weight, EventCount: len(c.EventIDs)})
	}
	// Strongest evidence first; name breaks ties for stable output.
	sort.SliceStable(a.Evidence, func(i, j int) bool {
		if a.Evidence[i].Weight != a.Evidence[j].Weight {
			return a.Evidence[i].Weight > a.Evidence[j].Weight
		}
		return a.Evidence[i].Name < a.Evidence[j].Name
	})
	if estimate != nil {
		a.PricingVersion = estimate.PricingVersion
		a.HourlyCostUSD = estimate.HourlyCostUSD
	}
	return a
}

// Alert sources.
const (
	SourceCloudTrail = "cloudtrail"
	SourceHost       = "host"
)

// FromHost builds an alert for a suspicious process. The command line and
// connection details stay in the scan output and evidence log; the alert
// carries only the host, process name, PID and indicator names.
func FromHost(f host.Finding, collectedAt, now time.Time) Alert {
	a := Alert{
		Schema:      Schema,
		GeneratedAt: now.UTC(),
		Source:      SourceHost,
		IncidentID:  f.IncidentID(),
		Principal:   fmt.Sprintf("host:%s process:%s pid:%d", f.Host, f.Name, f.PID),
		First:       collectedAt,
		Last:        collectedAt,
		Confidence:  f.Confidence,
		Evidence:    make([]Evidence, 0, len(f.Contributors)),
		Note:        Note,
	}
	for _, c := range f.Contributors {
		a.Evidence = append(a.Evidence, Evidence{Kind: "indicator", Name: string(c.Indicator), Weight: c.Weight, EventCount: 1})
	}
	sort.SliceStable(a.Evidence, func(i, j int) bool {
		if a.Evidence[i].Weight != a.Evidence[j].Weight {
			return a.Evidence[i].Weight > a.Evidence[j].Weight
		}
		return a.Evidence[i].Name < a.Evidence[j].Name
	})
	return a
}

// slackEscape escapes the characters Slack mrkdwn treats as control syntax.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func joinOrNone(vals []string) string {
	if len(vals) == 0 {
		return "none"
	}
	return strings.Join(vals, ", ")
}

// Render encodes the alert in the given format.
func Render(format Format, a Alert) ([]byte, error) {
	switch format {
	case FormatWebhook:
		return json.Marshal(a)
	case FormatSlack:
		return json.Marshal(slackMessage(a))
	}
	return nil, fmt.Errorf("%w: unknown format %q", ErrConfig, format)
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

func contextElements(a Alert) []slackText {
	els := []slackText{{Type: "mrkdwn", Text: Note}}
	if a.EvidenceHash != "" {
		h := a.EvidenceHash
		if len(h) > 16 {
			h = h[:16]
		}
		els = append(els, slackText{Type: "mrkdwn", Text: "Evidence record " + slackEscape(h)})
	}
	return els
}

func slackMessage(a Alert) slackPayload {
	title := fmt.Sprintf("Cloud Abuse Defender: %.1f%% confidence finding", a.Confidence)
	switch a.Update {
	case string(VerdictEscalated):
		title = "Escalated: " + title
	case string(VerdictReminder):
		title = "Reminder: " + title
	}

	evidence := make([]string, 0, len(a.Evidence))
	for _, e := range a.Evidence {
		evidence = append(evidence, fmt.Sprintf("%s (%.2f)", e.Name, e.Weight))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*Incident:* `%s`\n", slackEscape(a.IncidentID))
	if a.Source == SourceHost {
		fmt.Fprintf(&b, "*Process:* `%s`\n", slackEscape(a.Principal))
		fmt.Fprintf(&b, "*Observed:* %s\n", a.Last.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "*Principal:* `%s`\n", slackEscape(a.Principal))
		if len(a.Linked) > 0 {
			fmt.Fprintf(&b, "*Created identities:* %s\n", slackEscape(strings.Join(a.Linked, ", ")))
		}
		fmt.Fprintf(&b, "*Accounts:* %s\n", slackEscape(joinOrNone(a.AccountIDs)))
		fmt.Fprintf(&b, "*Regions:* %s\n", slackEscape(joinOrNone(a.Regions)))
		fmt.Fprintf(&b, "*Activity:* %s to %s\n", a.First.UTC().Format(time.RFC3339), a.Last.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "*Evidence:* %s", slackEscape(joinOrNone(evidence)))
	if d := a.Decision; d != nil {
		fmt.Fprintf(&b, "\n*Decision:* %s: %s", slackEscape(string(d.Action)), slackEscape(d.Reason))
		fmt.Fprintf(&b, "\n*Projected cost:* $%.2f", d.ProjectedCostUSD)
		if a.PricingVersion != "" {
			fmt.Fprintf(&b, " (pricing %s)", slackEscape(a.PricingVersion))
		}
		for _, w := range d.ForecastWarnings {
			fmt.Fprintf(&b, "\n:warning: %s", slackEscape(w))
		}
	}
	return slackPayload{
		Text: title,
		Blocks: []slackBlock{
			{Type: "header", Text: &slackText{Type: "plain_text", Text: title}},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: b.String()}},
			{Type: "context", Elements: contextElements(a)},
		},
	}
}

// Sender delivers alerts over HTTPS.
type Sender struct {
	// URL is the webhook endpoint. It is a secret and never appears in errors.
	URL    string
	Format Format
	// Client defaults to an http.Client with a 10s timeout.
	Client *http.Client
	// MaxAttempts defaults to 3. Only network errors, 429 and 5xx are retried.
	MaxAttempts int
	// Backoff is the delay before the first retry, doubling each time. Defaults to 1s.
	Backoff time.Duration
}

// Validate checks the sender configuration without revealing the URL.
func (s Sender) Validate() error {
	if _, err := ParseFormat(string(s.Format)); err != nil {
		return err
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: webhook URL is not a valid absolute URL", ErrConfig)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: webhook URL must use https", ErrConfig)
	}
	if s.MaxAttempts < 0 || s.Backoff < 0 {
		return fmt.Errorf("%w: attempts and backoff must not be negative", ErrConfig)
	}
	return nil
}

const maxErrorBody = 200

// Send renders and posts the alert, retrying transient failures.
func (s Sender) Send(ctx context.Context, a Alert) error {
	if err := s.Validate(); err != nil {
		return err
	}
	body, err := Render(s.Format, a)
	if err != nil {
		return err
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	attempts := s.MaxAttempts
	if attempts == 0 {
		attempts = 3
	}
	backoff := s.Backoff
	if backoff == 0 {
		backoff = time.Second
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		retry, err := s.post(ctx, client, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry || attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v (after %d attempt(s))", ErrSend, ctx.Err(), attempt)
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastErr
}

// post makes one attempt. It reports whether a failure is worth retrying.
func (s Sender) post(ctx context.Context, client *http.Client, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("%w: could not build request", ErrSend)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cloud-abuse-defender")
	resp, err := client.Do(req)
	if err != nil {
		// *url.Error embeds the full URL; report only the underlying cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return ctx.Err() == nil, fmt.Errorf("%w: %v", ErrSend, err)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	msg := strings.TrimSpace(string(snippet))
	if msg != "" {
		return retry, fmt.Errorf("%w: HTTP %d: %s", ErrSend, resp.StatusCode, msg)
	}
	return retry, fmt.Errorf("%w: HTTP %d", ErrSend, resp.StatusCode)
}
