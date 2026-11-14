package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
)

// Suppression stops named indicators from counting for matching principals:
// for example GPU launches by the ML platform's role. Rules are deliberately
// narrow. Each must name its indicators, give a reason and expire, and the
// evasion indicators can never be suppressed, because a suppressed principal
// is exactly what an attacker who compromises it would hide behind.
type Suppression struct {
	// Principal is matched against the acting principal; "*" matches any
	// run of characters.
	Principal  string                 `json:"principal"`
	Indicators []cloudtrail.Indicator `json:"indicators"`
	Reason     string                 `json:"reason"`
	Expires    time.Time              `json:"expires"`
}

// Suppressions is a versioned set of rules.
type Suppressions struct {
	Version string        `json:"version"`
	Rules   []Suppression `json:"rules"`
}

// unsuppressible indicators signal evasion of monitoring.
var unsuppressible = map[cloudtrail.Indicator]bool{
	cloudtrail.MonitoringTampering:    true,
	cloudtrail.BedrockLoggingDisabled: true,
}

// LoadSuppressions decodes and validates a suppression file. Unknown fields are rejected.
func LoadSuppressions(r io.Reader) (Suppressions, error) {
	var s Suppressions
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Suppressions{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return Suppressions{}, fmt.Errorf("%w: unexpected data after JSON document", ErrInvalid)
	}
	if s.Version == "" {
		return Suppressions{}, fmt.Errorf("%w: suppressions version is required", ErrInvalid)
	}
	for i, rule := range s.Rules {
		bad := func(msg string) (Suppressions, error) {
			return Suppressions{}, fmt.Errorf("%w: suppression rule %d: %s", ErrInvalid, i+1, msg)
		}
		switch {
		case strings.Trim(rule.Principal, "*") == "":
			return bad("principal must name something; a bare wildcard is not allowed")
		case len(rule.Indicators) == 0:
			return bad("indicators must be listed explicitly")
		case strings.TrimSpace(rule.Reason) == "":
			return bad("reason is required")
		case rule.Expires.IsZero():
			return bad("expires is required")
		}
		for _, ind := range rule.Indicators {
			if _, known := IndicatorWeights[ind]; !known {
				return bad(fmt.Sprintf("unknown indicator %q", ind))
			}
			if unsuppressible[ind] {
				return bad(fmt.Sprintf("%s signals evasion and cannot be suppressed", ind))
			}
		}
	}
	return s, nil
}

// wildcardMatch reports whether s matches pattern, where "*" matches any run
// of characters (including "/" and ":").
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// SuppressionHit reports what a rule removed, so suppression stays visible.
type SuppressionHit struct {
	Principal string               `json:"principal"`
	Indicator cloudtrail.Indicator `json:"indicator"`
	Events    int                  `json:"events"`
	Reason    string               `json:"reason"`
}

// Apply returns a copy of events with suppressed indicators removed, what
// was removed, and how many rules were skipped because they have expired.
func (s Suppressions) Apply(events []cloudtrail.Event, now time.Time) (out []cloudtrail.Event, hits []SuppressionHit, expired int) {
	var active []Suppression
	for _, rule := range s.Rules {
		if now.Before(rule.Expires) {
			active = append(active, rule)
		} else {
			expired++
		}
	}
	type hitKey struct {
		principal string
		ind       cloudtrail.Indicator
	}
	counts := map[hitKey]*SuppressionHit{}
	out = make([]cloudtrail.Event, len(events))
	for i, ev := range events {
		out[i] = ev
		if len(ev.Indicators) == 0 {
			continue
		}
		principal := principalKey(ev)
		var kept []cloudtrail.Indicator
		for _, ind := range ev.Indicators {
			reason := ""
			for _, rule := range active {
				if !wildcardMatch(rule.Principal, principal) {
					continue
				}
				for _, ri := range rule.Indicators {
					if ri == ind {
						reason = rule.Reason
					}
				}
				if reason != "" {
					break
				}
			}
			if reason == "" {
				kept = append(kept, ind)
				continue
			}
			k := hitKey{principal, ind}
			if counts[k] == nil {
				counts[k] = &SuppressionHit{Principal: principal, Indicator: ind, Reason: reason}
			}
			counts[k].Events++
		}
		out[i].Indicators = kept
	}
	for _, h := range counts {
		hits = append(hits, *h)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Principal != hits[j].Principal {
			return hits[i].Principal < hits[j].Principal
		}
		return hits[i].Indicator < hits[j].Indicator
	})
	return out, hits, expired
}
