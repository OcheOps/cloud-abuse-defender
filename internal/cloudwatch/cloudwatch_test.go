package cloudwatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
)

var (
	start = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	end   = start.Add(30 * time.Minute)
)

func open(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestBuildQueries(t *testing.T) {
	q, err := BuildQueries([]string{"b.model", " a.model:1 ", "b.model"}, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 4 {
		t.Fatalf("want 4 queries for 2 unique models, got %d", len(q))
	}
	first := q[0]
	if first.ID != "m0_in" || first.Label != "cad:InputTokenCount:a.model:1" || !first.ReturnData ||
		first.MetricStat.Stat != "Sum" || first.MetricStat.Period != 300 ||
		first.MetricStat.Metric.Namespace != "AWS/Bedrock" ||
		!reflect.DeepEqual(first.MetricStat.Metric.Dimensions, []Dimension{{Name: "ModelId", Value: "a.model:1"}}) {
		t.Fatalf("unexpected first query: %+v", first)
	}
	if q[1].ID != "m0_out" || q[1].MetricStat.Metric.MetricName != "OutputTokenCount" || q[2].ID != "m1_in" {
		t.Fatalf("unexpected ordering: %+v", q)
	}
	// The AWS CLI expects exactly these field names.
	raw, _ := json.Marshal(q[0])
	for _, field := range []string{`"Id"`, `"MetricStat"`, `"Metric"`, `"Namespace"`, `"MetricName"`, `"Dimensions"`, `"Period"`, `"Stat"`, `"Label"`, `"ReturnData"`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("query JSON missing %s: %s", field, raw)
		}
	}
}

func TestBuildQueriesRejectsInvalid(t *testing.T) {
	many := make([]string, 251)
	for i := range many {
		many[i] = "m" + strings.Repeat("x", i+1)
	}
	for name, tc := range map[string]struct {
		models []string
		period int
	}{
		"no models":       {nil, 300},
		"empty model":     {[]string{"a", " "}, 300},
		"zero period":     {[]string{"a"}, 0},
		"odd period":      {[]string{"a"}, 90},
		"too many models": {many, 300},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildQueries(tc.models, tc.period); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestModelsFromListMetrics(t *testing.T) {
	models, err := ModelsFromListMetrics(open(t, filepath.Join("testdata", "list-metrics.json")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(models, []string{"example.text-model-large", "example.text-model-small"}) {
		t.Fatalf("got %v", models)
	}
	if _, err := ModelsFromListMetrics(strings.NewReader(`{"Metrics":[]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty list: want ErrInvalid, got %v", err)
	}
	if _, err := ModelsFromListMetrics(strings.NewReader(`nope`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad JSON: want ErrInvalid, got %v", err)
	}
}

// Converting the exported metrics must reproduce the hand-written example
// usage, and price to the same documented $56/hour.
func TestUsageFromResultsMatchesExample(t *testing.T) {
	u, err := UsageFromResults(open(t, filepath.Join("testdata", "get-metric-data.json")), "us-east-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	want, err := cost.LoadUsage(open(t, filepath.Join("..", "..", "examples", "usage.example.json")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u, want) {
		t.Fatalf("converted usage differs from example:\n got %+v\nwant %+v", u, want)
	}
	p, err := cost.LoadPricing(open(t, filepath.Join("..", "..", "examples", "pricing.example.json")))
	if err != nil {
		t.Fatal(err)
	}
	est, err := cost.EstimateBedrock(u, p, cost.Options{Now: end})
	if err != nil {
		t.Fatal(err)
	}
	if est.HourlyCostUSD != 56 {
		t.Fatalf("hourly %v, want 56", est.HourlyCostUSD)
	}
}

func TestUsageFromResultsMergesPages(t *testing.T) {
	doc := `{"MetricDataResults":[
		{"Id":"m0_in","Label":"cad:InputTokenCount:m:1","Timestamps":["2026-11-04T10:00:00Z"],"Values":[10.4],"StatusCode":"Complete"},
		{"Id":"m0_in","Label":"cad:InputTokenCount:m:1","Timestamps":["2026-11-04T10:05:00Z"],"Values":[5.3],"StatusCode":"Complete"}]}`
	u, err := UsageFromResults(strings.NewReader(doc), "r", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Models) != 1 || u.Models[0].ModelID != "m:1" || u.Models[0].InputTokens != 16 || u.Models[0].OutputTokens != 0 {
		t.Fatalf("pages not merged: %+v", u.Models)
	}
}

func TestUsageFromResultsEmptySeries(t *testing.T) {
	doc := `{"MetricDataResults":[{"Id":"m0_in","Label":"cad:InputTokenCount:idle","Timestamps":[],"Values":[],"StatusCode":"Complete"}]}`
	u, err := UsageFromResults(strings.NewReader(doc), "r", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Models) != 1 || u.Models[0].InputTokens != 0 {
		t.Fatalf("idle model must be reported with zero tokens: %+v", u.Models)
	}
}

func TestUsageFromResultsRejectsInvalid(t *testing.T) {
	ok := func(label, status, ts, val string) string {
		return `{"MetricDataResults":[{"Id":"x","Label":"` + label + `","Timestamps":[` + ts + `],"Values":[` + val + `],"StatusCode":"` + status + `"}]}`
	}
	const good = `"2026-11-04T10:00:00Z"`
	tests := map[string]struct {
		doc        string
		region     string
		start, end time.Time
	}{
		"not json":           {`nope`, "r", start, end},
		"no results key":     {`{}`, "r", start, end},
		"no results":         {`{"MetricDataResults":[]}`, "r", start, end},
		"foreign label":      {ok("InputTokenCount", "Complete", good, "1"), "r", start, end},
		"unknown metric":     {ok("cad:Invocations:m", "Complete", good, "1"), "r", start, end},
		"label without id":   {ok("cad:InputTokenCount:", "Complete", good, "1"), "r", start, end},
		"partial data":       {ok("cad:InputTokenCount:m", "PartialData", good, "1"), "r", start, end},
		"length mismatch":    {ok("cad:InputTokenCount:m", "Complete", good, "1,2"), "r", start, end},
		"before window":      {ok("cad:InputTokenCount:m", "Complete", `"2026-11-04T09:55:00Z"`, "1"), "r", start, end},
		"at window end":      {ok("cad:InputTokenCount:m", "Complete", `"2026-11-04T10:30:00Z"`, "1"), "r", start, end},
		"negative value":     {ok("cad:InputTokenCount:m", "Complete", good, "-1"), "r", start, end},
		"overflow":           {ok("cad:InputTokenCount:m", "Complete", good, "1e300"), "r", start, end},
		"no region":          {ok("cad:InputTokenCount:m", "Complete", good, "1"), "", start, end},
		"reversed window":    {ok("cad:InputTokenCount:m", "Complete", good, "1"), "r", end, start},
		"zero window bounds": {ok("cad:InputTokenCount:m", "Complete", good, "1"), "r", time.Time{}, end},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := UsageFromResults(strings.NewReader(tc.doc), tc.region, tc.start, tc.end); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestLabelRoundTrip(t *testing.T) {
	for _, model := range []string{"plain", "anthropic.claude-v2:1", "us.meta.llama3-1-70b-instruct-v1:0"} {
		metric, got, ok := parseLabel(label(outputMetric, model))
		if !ok || metric != outputMetric || got != model {
			t.Errorf("round trip of %q gave %q %q %v", model, metric, got, ok)
		}
	}
}
