package cost

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ec2Table() EC2PricingTable {
	return EC2PricingTable{
		Version: "ec2-v1", Provider: "aws-ec2", Currency: "USD", EffectiveDate: t0.Add(-24 * time.Hour),
		Regions: map[string]map[string]float64{
			"us-east-1": {"p4d.24xlarge": 30, "t3.micro": 0.01},
			"us-west-2": {"p4d.24xlarge": 32},
		},
	}
}

func TestEstimateEC2(t *testing.T) {
	est, err := EstimateEC2([]InstanceLaunch{
		{"us-east-1", "p4d.24xlarge", 20}, {"us-west-2", "p4d.24xlarge", 2}, {"us-east-1", "t3.micro", 1},
	}, ec2Table(), opts())
	if err != nil {
		t.Fatal(err)
	}
	if !approx(est.HourlyCostUSD, 664.01) || len(est.Warnings) != 0 || est.PricingVersion != "ec2-v1" {
		t.Fatalf("unexpected estimate: %+v", est)
	}
	if len(est.Lines) != 3 || !approx(est.Lines[0].HourlyCostUSD, 600) || !est.Lines[1].Priced {
		t.Fatalf("unexpected lines: %+v", est.Lines)
	}
	if empty, err := EstimateEC2(nil, ec2Table(), opts()); err != nil || empty.HourlyCostUSD != 0 || len(empty.Warnings) != 0 || empty.Lines == nil {
		t.Fatalf("no launches: %+v %v", empty, err)
	}
}

func TestEstimateEC2Warnings(t *testing.T) {
	launch := []InstanceLaunch{{"us-east-1", "p4d.24xlarge", 1}}
	for name, tc := range map[string]struct {
		mutate   func(*EC2PricingTable, *[]InstanceLaunch)
		want     string
		wantCost float64
	}{
		"unpriced type":   {func(_ *EC2PricingTable, l *[]InstanceLaunch) { (*l)[0].InstanceType = "x1e.32xlarge" }, "no EC2 price for x1e.32xlarge in us-east-1", 0},
		"unpriced region": {func(_ *EC2PricingTable, l *[]InstanceLaunch) { (*l)[0].Region = "ap-south-1" }, "in ap-south-1", 0},
		"stale":           {func(p *EC2PricingTable, _ *[]InstanceLaunch) { p.EffectiveDate = now.Add(-31 * 24 * time.Hour) }, "older than", 30},
		"future":          {func(p *EC2PricingTable, _ *[]InstanceLaunch) { p.EffectiveDate = now.Add(time.Hour) }, "not effective until", 30},
	} {
		t.Run(name, func(t *testing.T) {
			p, l := ec2Table(), append([]InstanceLaunch(nil), launch...)
			tc.mutate(&p, &l)
			est, err := EstimateEC2(l, p, opts())
			if err != nil {
				t.Fatal(err)
			}
			if len(est.Warnings) != 1 || !strings.Contains(est.Warnings[0], tc.want) || !approx(est.HourlyCostUSD, tc.wantCost) {
				t.Fatalf("got %+v", est)
			}
		})
	}
}

func TestEstimateEC2RejectsInvalid(t *testing.T) {
	ok := []InstanceLaunch{{"us-east-1", "t3.micro", 1}}
	for name, tc := range map[string]struct {
		mutate func(*EC2PricingTable, *[]InstanceLaunch, *Options)
	}{
		"no version":     {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Version = "" }},
		"wrong provider": {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Provider = "aws-bedrock" }},
		"non-USD":        {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Currency = "EUR" }},
		"no date":        {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.EffectiveDate = time.Time{} }},
		"no regions":     {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Regions = nil }},
		"empty region":   {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Regions["eu-west-1"] = nil }},
		"negative rate":  {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Regions["us-east-1"]["t3.micro"] = -1 }},
		"NaN rate": {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) {
			p.Regions["us-east-1"]["t3.micro"] = math.NaN()
		}},
		"empty type":     {func(p *EC2PricingTable, _ *[]InstanceLaunch, _ *Options) { p.Regions["us-east-1"][""] = 1 }},
		"zero count":     {func(_ *EC2PricingTable, l *[]InstanceLaunch, _ *Options) { (*l)[0].Count = 0 }},
		"no launch type": {func(_ *EC2PricingTable, l *[]InstanceLaunch, _ *Options) { (*l)[0].InstanceType = "" }},
		"no now":         {func(_ *EC2PricingTable, _ *[]InstanceLaunch, o *Options) { o.Now = time.Time{} }},
		"negative age":   {func(_ *EC2PricingTable, _ *[]InstanceLaunch, o *Options) { o.MaxPricingAge = -1 }},
		"overflow": {func(p *EC2PricingTable, l *[]InstanceLaunch, _ *Options) {
			p.Regions["us-east-1"]["t3.micro"] = math.MaxFloat64
			(*l)[0].Count = 10
		}},
	} {
		t.Run(name, func(t *testing.T) {
			p, l, o := ec2Table(), append([]InstanceLaunch(nil), ok...), opts()
			tc.mutate(&p, &l, &o)
			if _, err := EstimateEC2(l, p, o); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestEC2ExampleFile(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "examples", "ec2-pricing.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := LoadEC2Pricing(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Version, "example-") || !strings.Contains(p.Source, "ILLUSTRATIVE") {
		t.Fatalf("example EC2 pricing must be clearly marked as illustrative: %+v", p)
	}
	if _, err := LoadEC2Pricing(strings.NewReader(`{"version":"v","surprise":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
}
