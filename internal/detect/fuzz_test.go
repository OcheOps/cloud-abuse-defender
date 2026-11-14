package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
)

func FuzzLoadSuppressions(f *testing.F) {
	f.Add(`{"version":"s1","rules":[{"principal":"arn:aws:iam::*:user/ml-*","indicators":["gpu_instance_launch"],"reason":"r","expires":"2027-01-01T00:00:00Z"}]}`)
	f.Add(`{"version":"s1","rules":[]}`)
	f.Fuzz(func(t *testing.T, doc string) {
		s, err := LoadSuppressions(strings.NewReader(doc))
		if err != nil {
			return
		}
		for _, rule := range s.Rules {
			for _, ind := range rule.Indicators {
				if unsuppressible[ind] {
					t.Fatalf("loaded a rule suppressing %s", ind)
				}
			}
			if strings.Trim(rule.Principal, "*") == "" {
				t.Fatal("loaded a bare-wildcard rule")
			}
		}
		ev := cloudtrail.Event{PrincipalARN: "arn:aws:iam::1:user/ml-x", Indicators: []cloudtrail.Indicator{cloudtrail.MonitoringTampering, cloudtrail.GPUInstanceLaunch}}
		out, _, _ := s.Apply([]cloudtrail.Event{ev}, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
		kept := false
		for _, ind := range out[0].Indicators {
			kept = kept || ind == cloudtrail.MonitoringTampering
		}
		if !kept {
			t.Fatal("an evasion indicator was suppressed")
		}
	})
}

func FuzzWildcardMatch(f *testing.F) {
	f.Add("a*c", "abc")
	f.Add("**", "")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		wildcardMatch(pattern, s)
		if !strings.Contains(s, "*") && !wildcardMatch(s, s) {
			t.Fatalf("%q must match itself", s)
		}
	})
}
