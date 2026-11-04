// Package cloudwatch converts AWS Bedrock token metrics exported from
// CloudWatch into the usage observations that internal/cost prices.
//
// It makes no AWS calls and handles no credentials. The workflow is:
//
//  1. BuildQueries writes a metric-data-queries file for the models of interest.
//  2. The operator runs the read-only AWS CLI command
//     aws cloudwatch get-metric-data --metric-data-queries file://queries.json ...
//     with their own credentials (only cloudwatch:GetMetricData is needed).
//  3. UsageFromResults sums the returned InputTokenCount and OutputTokenCount
//     per model into a cost.Usage.
//
// Each query's Label encodes its metric and model ID, so the results file
// alone identifies every series.
package cloudwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
)

// ErrInvalid is wrapped by every validation error in this package.
var ErrInvalid = errors.New("invalid cloudwatch input")

const (
	namespace    = "AWS/Bedrock"
	dimension    = "ModelId"
	inputMetric  = "InputTokenCount"
	outputMetric = "OutputTokenCount"
	labelPrefix  = "cad"
	// maxQueries is the GetMetricData limit per request; each model needs two.
	maxQueries = 500
	// DefaultPeriod is the aggregation period, in seconds, for generated queries.
	DefaultPeriod = 300
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Query is one entry of a GetMetricData metric-data-queries file, using the
// field names the AWS CLI expects.
type Query struct {
	ID         string     `json:"Id"`
	MetricStat MetricStat `json:"MetricStat"`
	Label      string     `json:"Label"`
	ReturnData bool       `json:"ReturnData"`
}

// MetricStat selects a metric and statistic.
type MetricStat struct {
	Metric Metric `json:"Metric"`
	Period int    `json:"Period"`
	Stat   string `json:"Stat"`
}

// Metric identifies a CloudWatch metric.
type Metric struct {
	Namespace  string      `json:"Namespace"`
	MetricName string      `json:"MetricName"`
	Dimensions []Dimension `json:"Dimensions"`
}

// Dimension is a CloudWatch metric dimension.
type Dimension struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

func label(metric, model string) string { return labelPrefix + ":" + metric + ":" + model }

// parseLabel reverses label. Model IDs may contain colons (for example
// "anthropic.claude-v2:1"), so only the first two separators are split.
func parseLabel(l string) (metric, model string, ok bool) {
	parts := strings.SplitN(l, ":", 3)
	if len(parts) != 3 || parts[0] != labelPrefix || parts[2] == "" {
		return "", "", false
	}
	if parts[1] != inputMetric && parts[1] != outputMetric {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// BuildQueries returns Sum queries for input and output token counts of each
// model, deduplicated and sorted. period is in seconds and must be a positive
// multiple of 60.
func BuildQueries(models []string, period int) ([]Query, error) {
	if period <= 0 || period%60 != 0 {
		return nil, invalid("period must be a positive multiple of 60 seconds, got %d", period)
	}
	seen := map[string]bool{}
	var ids []string
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m == "" {
			return nil, invalid("empty model ID")
		}
		if !seen[m] {
			seen[m] = true
			ids = append(ids, m)
		}
	}
	if len(ids) == 0 {
		return nil, invalid("no models given")
	}
	if 2*len(ids) > maxQueries {
		return nil, invalid("%d models need %d queries; GetMetricData allows %d per request", len(ids), 2*len(ids), maxQueries)
	}
	sort.Strings(ids)
	queries := make([]Query, 0, 2*len(ids))
	for i, m := range ids {
		for _, metric := range []string{inputMetric, outputMetric} {
			suffix := "in"
			if metric == outputMetric {
				suffix = "out"
			}
			queries = append(queries, Query{
				// Ids must match ^[a-z][a-zA-Z0-9_]*$, so the model lives in the label.
				ID: fmt.Sprintf("m%d_%s", i, suffix),
				MetricStat: MetricStat{
					Metric: Metric{Namespace: namespace, MetricName: metric, Dimensions: []Dimension{{Name: dimension, Value: m}}},
					Period: period,
					Stat:   "Sum",
				},
				Label:      label(metric, m),
				ReturnData: true,
			})
		}
	}
	return queries, nil
}

// ModelsFromListMetrics extracts Bedrock model IDs from the output of
// "aws cloudwatch list-metrics --namespace AWS/Bedrock".
func ModelsFromListMetrics(r io.Reader) ([]string, error) {
	var doc struct {
		Metrics []Metric `json:"Metrics"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	seen := map[string]bool{}
	var models []string
	for _, m := range doc.Metrics {
		if m.Namespace != namespace || (m.MetricName != inputMetric && m.MetricName != outputMetric) {
			continue
		}
		for _, d := range m.Dimensions {
			if d.Name == dimension && d.Value != "" && !seen[d.Value] {
				seen[d.Value] = true
				models = append(models, d.Value)
			}
		}
	}
	if len(models) == 0 {
		return nil, invalid("no Bedrock token metrics with a ModelId dimension found")
	}
	sort.Strings(models)
	return models, nil
}

// result is one MetricDataResults entry from get-metric-data output.
type result struct {
	ID         string      `json:"Id"`
	Label      string      `json:"Label"`
	Timestamps []time.Time `json:"Timestamps"`
	Values     []float64   `json:"Values"`
	StatusCode string      `json:"StatusCode"`
}

// UsageFromResults sums get-metric-data output into a usage observation for
// [start, end). start and end must be the times passed to the AWS CLI; every
// datapoint must fall inside them, which catches mismatched arguments.
//
// Results that are not "Complete" are rejected: partial data would
// underestimate spend. Repeated labels (from paginated output) are summed.
func UsageFromResults(r io.Reader, region string, start, end time.Time) (cost.Usage, error) {
	if region == "" {
		return cost.Usage{}, invalid("region is required")
	}
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return cost.Usage{}, invalid("end must be after start")
	}
	var doc struct {
		MetricDataResults *[]result `json:"MetricDataResults"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return cost.Usage{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if doc.MetricDataResults == nil {
		return cost.Usage{}, invalid(`missing "MetricDataResults"`)
	}

	type totals struct{ in, out float64 }
	byModel := map[string]*totals{}
	for _, res := range *doc.MetricDataResults {
		metric, model, ok := parseLabel(res.Label)
		if !ok {
			return cost.Usage{}, invalid("result %q has label %q; generate queries with 'cad bedrock-queries' so labels identify the model", res.ID, res.Label)
		}
		if res.StatusCode != "Complete" {
			return cost.Usage{}, invalid("result %q status is %q, not Complete; fetch all pages before converting", res.ID, res.StatusCode)
		}
		if len(res.Timestamps) != len(res.Values) {
			return cost.Usage{}, invalid("result %q has %d timestamps but %d values", res.ID, len(res.Timestamps), len(res.Values))
		}
		t := byModel[model]
		if t == nil {
			t = &totals{}
			byModel[model] = t
		}
		for i, v := range res.Values {
			ts := res.Timestamps[i]
			if ts.Before(start) || !ts.Before(end) {
				return cost.Usage{}, invalid("result %q has a datapoint at %s outside the window %s to %s; pass the same times given to the AWS CLI",
					res.ID, ts.UTC().Format(time.RFC3339), start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
			}
			if v < 0 || math.IsInf(v, 0) {
				return cost.Usage{}, invalid("result %q has an invalid token count %v", res.ID, v)
			}
			if metric == inputMetric {
				t.in += v
			} else {
				t.out += v
			}
		}
	}
	if len(byModel) == 0 {
		return cost.Usage{}, invalid("no metric results")
	}

	models := make([]string, 0, len(byModel))
	for m := range byModel {
		models = append(models, m)
	}
	sort.Strings(models)
	u := cost.Usage{Region: region, WindowStart: start.UTC(), WindowEnd: end.UTC()}
	for _, m := range models {
		t := byModel[m]
		if t.in > math.MaxInt64 || t.out > math.MaxInt64 {
			return cost.Usage{}, invalid("token count for %q overflows", m)
		}
		u.Models = append(u.Models, cost.ModelUsage{ModelID: m, InputTokens: int64(math.Round(t.in)), OutputTokens: int64(math.Round(t.out))})
	}
	return u, u.Validate()
}
