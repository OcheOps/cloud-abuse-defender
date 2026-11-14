package cost

import (
	"fmt"
	"io"
	"math"
	"time"
)

// EC2PricingTable is a versioned set of on-demand hourly prices, in USD per
// instance-hour, keyed by region and then instance type.
type EC2PricingTable struct {
	Version       string                        `json:"version"`
	Provider      string                        `json:"provider"`
	Currency      string                        `json:"currency"`
	EffectiveDate time.Time                     `json:"effective_date"`
	Source        string                        `json:"source"`
	Regions       map[string]map[string]float64 `json:"regions"`
}

// Validate checks that the table is internally consistent.
func (p EC2PricingTable) Validate() error {
	switch {
	case p.Version == "":
		return invalid("EC2 pricing version is required")
	case p.Provider != "aws-ec2":
		return invalid("unsupported pricing provider %q (want \"aws-ec2\")", p.Provider)
	case p.Currency != "USD":
		return invalid("unsupported currency %q (want \"USD\")", p.Currency)
	case p.EffectiveDate.IsZero():
		return invalid("EC2 pricing effective_date is required")
	case len(p.Regions) == 0:
		return invalid("EC2 pricing table has no regions")
	}
	for region, types := range p.Regions {
		if region == "" || len(types) == 0 {
			return invalid("EC2 pricing has an empty region name or a region with no instance types")
		}
		for typ, rate := range types {
			if typ == "" || !validRate(rate) {
				return invalid("EC2 price for %q in %s is missing a type, negative or not finite", typ, region)
			}
		}
	}
	return nil
}

// LoadEC2Pricing decodes and validates an EC2 pricing table. Unknown fields are rejected.
func LoadEC2Pricing(r io.Reader) (EC2PricingTable, error) {
	var p EC2PricingTable
	if err := decodeStrict(r, &p); err != nil {
		return EC2PricingTable{}, err
	}
	return p, p.Validate()
}

// InstanceLaunch is a number of instances of one type started in one region.
type InstanceLaunch struct {
	Region       string `json:"region"`
	InstanceType string `json:"instance_type"`
	Count        int    `json:"count"`
}

// EC2Line is the per-launch breakdown of an estimate.
type EC2Line struct {
	InstanceLaunch
	HourlyCostUSD float64 `json:"hourly_cost_usd"`
	Priced        bool    `json:"priced"`
}

// EC2Estimate is the hourly cost of a set of launched instances if they are
// all left running. It is a ceiling for on-demand Linux pricing: instances
// that were later stopped still count, and Spot, Savings Plans, storage and
// data transfer are not modelled.
//
// Any entry in Warnings means the estimate may be wrong (usually low) and
// callers should degrade to alert-only.
type EC2Estimate struct {
	PricingVersion string    `json:"pricing_version"`
	HourlyCostUSD  float64   `json:"hourly_cost_usd"`
	Lines          []EC2Line `json:"lines"`
	Warnings       []string  `json:"warnings,omitempty"`
}

// EstimateEC2 prices launched instances. Options.MinWindow is not used.
func EstimateEC2(launches []InstanceLaunch, p EC2PricingTable, opt Options) (EC2Estimate, error) {
	if err := p.Validate(); err != nil {
		return EC2Estimate{}, err
	}
	if opt.Now.IsZero() {
		return EC2Estimate{}, invalid("options.Now is required")
	}
	if opt.MaxPricingAge < 0 {
		return EC2Estimate{}, invalid("options durations must not be negative")
	}
	est := EC2Estimate{PricingVersion: p.Version, Lines: make([]EC2Line, 0, len(launches))}
	if opt.MaxPricingAge > 0 && opt.Now.Sub(p.EffectiveDate) > opt.MaxPricingAge {
		est.Warnings = append(est.Warnings, fmt.Sprintf("EC2 pricing %q is older than %s", p.Version, opt.MaxPricingAge))
	}
	if p.EffectiveDate.After(opt.Now) {
		est.Warnings = append(est.Warnings, fmt.Sprintf("EC2 pricing %q is not effective until %s", p.Version, p.EffectiveDate.Format(time.RFC3339)))
	}
	for _, l := range launches {
		if l.Region == "" || l.InstanceType == "" || l.Count <= 0 {
			return EC2Estimate{}, invalid("launch needs a region, an instance type and a positive count: %+v", l)
		}
		line := EC2Line{InstanceLaunch: l}
		if rate, ok := p.Regions[l.Region][l.InstanceType]; ok {
			line.Priced = true
			line.HourlyCostUSD = rate * float64(l.Count)
		} else {
			est.Warnings = append(est.Warnings, fmt.Sprintf("no EC2 price for %s in %s in pricing %q; its cost is excluded", l.InstanceType, l.Region, p.Version))
		}
		est.HourlyCostUSD += line.HourlyCostUSD
		est.Lines = append(est.Lines, line)
	}
	if math.IsInf(est.HourlyCostUSD, 0) || math.IsNaN(est.HourlyCostUSD) {
		return EC2Estimate{}, invalid("hourly cost overflow")
	}
	return est, nil
}
