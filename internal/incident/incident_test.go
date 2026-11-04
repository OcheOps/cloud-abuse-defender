package incident

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

const principal = "arn:aws:iam::123456789012:user/ci-deploy"

type harness struct {
	t    *testing.T
	log  *evidence.Log
	recs []evidence.Record
}

func newHarness(t *testing.T) *harness {
	l, err := evidence.Open(filepath.Join(t.TempDir(), "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &harness{t: t, log: l}
}

func (h *harness) append(kind, id string, data any) evidence.Record {
	h.t.Helper()
	r, err := h.log.Append(kind, id, data, t0)
	if err != nil {
		h.t.Fatal(err)
	}
	h.recs = append(h.recs, r)
	return r
}

func (h *harness) finding(id string, eligible bool, conf float64) evidence.Record {
	act := policy.Alert
	if eligible {
		act = policy.RecommendContainment
	}
	return h.append(KindFinding, id, FindingData{
		Finding:  detect.Finding{Principal: principal, Confidence: conf},
		Decision: &policy.Decision{Action: act, EligibleForContainment: eligible},
	})
}

func (h *harness) state(id string, now time.Time) Status {
	h.t.Helper()
	s, err := StatusOf(h.recs, id, now)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

var op = Decider{Operator: "alice", RecordedBy: "alice-laptop", Reason: "confirmed stolen key"}

func approveReq(id string) ApproveRequest {
	return ApproveRequest{Decider: op, IncidentID: id, Principal: principal, Action: DeactivateAccessKeys, TTL: 4 * time.Hour}
}

func TestLifecycle(t *testing.T) {
	h := newHarness(t)
	f := h.finding("inc_a", true, 98.6)
	if s := h.state("inc_a", t0); s.State != StatePending || s.FindingRecord != f.Hash {
		t.Fatalf("want pending, got %+v", s)
	}

	ap, err := Approve(h.recs, approveReq("inc_a"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if ap.FindingRecord != f.Hash || !ap.ExpiresAt.Equal(t0.Add(4*time.Hour)) || ap.Principal != principal {
		t.Fatalf("unexpected approval: %+v", ap)
	}
	apRec := h.append(KindApproval, "inc_a", ap)
	s := h.state("inc_a", t0.Add(time.Hour))
	if s.State != StateApproved || s.DecisionRecord != apRec.Hash || s.Approval.Operator != "alice" {
		t.Fatalf("want approved, got %+v", s)
	}
	if _, err := Approve(h.recs, approveReq("inc_a"), t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("double approval must be refused: %v", err)
	}
	if _, err := Reject(h.recs, "inc_a", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("rejecting an active approval must be refused: %v", err)
	}
	if s := h.state("inc_a", t0.Add(4*time.Hour)); s.State != StateExpired {
		t.Fatalf("want expired at the deadline, got %s", s.State)
	}

	rv, err := Revoke(h.recs, "inc_a", op, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rv.ApprovalRecord != apRec.Hash {
		t.Fatalf("revocation must point at the approval: %+v", rv)
	}
	h.append(KindRevocation, "inc_a", rv)
	if s := h.state("inc_a", t0.Add(time.Hour)); s.State != StateRevoked {
		t.Fatalf("want revoked, got %s", s.State)
	}
	if _, err := Revoke(h.recs, "inc_a", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoking twice must be refused: %v", err)
	}

	rj, err := Reject(h.recs, "inc_a", op, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.append(KindRejection, "inc_a", rj)
	if s := h.state("inc_a", t0.Add(time.Hour)); s.State != StateRejected {
		t.Fatalf("want rejected, got %s", s.State)
	}
	if _, err := Approve(h.recs, approveReq("inc_a"), t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("approving a rejected finding must be refused: %v", err)
	}

	// A newer finding needs a fresh decision.
	f2 := h.finding("inc_a", true, 99)
	if s := h.state("inc_a", t0); s.State != StatePending || s.FindingRecord != f2.Hash {
		t.Fatalf("newer finding must reset to pending: %+v", s)
	}
}

func TestApprovalRefusals(t *testing.T) {
	h := newHarness(t)
	h.finding("inc_ok", true, 90)
	h.finding("inc_low", false, 60)
	tests := map[string]func(*ApproveRequest){
		"not eligible":       func(r *ApproveRequest) { r.IncidentID = "inc_low" },
		"unknown incident":   func(r *ApproveRequest) { r.IncidentID = "inc_missing" },
		"principal mismatch": func(r *ApproveRequest) { r.Principal = "arn:aws:iam::123456789012:user/someone-else" },
		"unknown action":     func(r *ApproveRequest) { r.Action = "terminate-everything" },
		"zero ttl":           func(r *ApproveRequest) { r.TTL = 0 },
		"ttl too long":       func(r *ApproveRequest) { r.TTL = MaxApprovalTTL + time.Second },
		"no operator":        func(r *ApproveRequest) { r.Operator = "  " },
		"no reason":          func(r *ApproveRequest) { r.Reason = "" },
		"long reason":        func(r *ApproveRequest) { r.Reason = strings.Repeat("x", maxReasonLen+1) },
		"long operator":      func(r *ApproveRequest) { r.Operator = strings.Repeat("x", maxOperatorLen+1) },
		"control chars":      func(r *ApproveRequest) { r.Operator = "alice\nbob" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := approveReq("inc_ok")
			mutate(&req)
			if _, err := Approve(h.recs, req, t0); !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
		})
	}
	if _, err := Approve(h.recs, approveReq("inc_ok"), t0); err != nil {
		t.Fatalf("control: valid request refused: %v", err)
	}
	if _, err := Approve(h.recs, ApproveRequest{Decider: op, IncidentID: "inc_ok", Principal: principal, Action: AttachDenyAllPolicy, TTL: MaxApprovalTTL}, t0); err != nil {
		t.Fatalf("deny-all at max TTL must be allowed: %v", err)
	}
}

func TestRejectAndRevokeRefusals(t *testing.T) {
	h := newHarness(t)
	h.finding("inc_low", false, 40)
	h.finding("inc_ok", true, 90)
	if _, err := Reject(h.recs, "inc_low", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("rejecting a non-eligible incident: %v", err)
	}
	if _, err := Reject(h.recs, "inc_missing", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("rejecting unknown incident: %v", err)
	}
	if _, err := Reject(h.recs, "inc_ok", Decider{Operator: "a"}, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("reject without reason: %v", err)
	}
	if _, err := Revoke(h.recs, "inc_ok", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoke without approval: %v", err)
	}
	if _, err := Revoke(h.recs, "inc_ok", Decider{Reason: "x"}, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoke without operator: %v", err)
	}
	if _, err := Revoke(h.recs, "inc_missing", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoke unknown incident: %v", err)
	}
	h.append(KindRejection, "inc_ok", RejectionData{Decider: op, FindingRecord: h.recs[1].Hash})
	if _, err := Reject(h.recs, "inc_ok", op, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("double rejection: %v", err)
	}
}

func TestSummarize(t *testing.T) {
	h := newHarness(t)
	h.finding("inc_b", false, 40)
	h.finding("inc_a", true, 90)
	h.append(KindNotification, "inc_a", NotificationData{Status: "sent"})
	// Decisions on unknown incidents and stale finding records are ignored.
	h.append(KindApproval, "inc_ghost", ApprovalData{FindingRecord: "x"})
	h.append(KindApproval, "inc_a", ApprovalData{FindingRecord: "stale"})
	h.append(KindRevocation, "inc_ghost", RevocationData{ApprovalRecord: "x"})
	all, err := Summarize(h.recs, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].IncidentID != "inc_a" || all[0].State != StatePending || all[1].State != StateNotEligible {
		t.Fatalf("unexpected summary: %+v", all)
	}
}

func TestMalformedRecords(t *testing.T) {
	for _, kind := range []string{KindFinding, KindApproval, KindRevocation} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			h.finding("inc_a", true, 90)
			h.append(kind, "inc_a", "not an object")
			if _, err := Summarize(h.recs, t0); err == nil {
				t.Fatal("malformed record must be reported")
			}
		})
	}
	h := newHarness(t)
	h.finding("inc_a", true, 90)
	h.append(KindApproval, "inc_a", map[string]any{"finding_record": h.recs[0].Hash, "expires_at": 5})
	if _, err := StatusOf(h.recs, "inc_a", t0); err == nil {
		t.Fatal("malformed approval body must be reported")
	}
}

func TestParseAction(t *testing.T) {
	for _, a := range []string{"deactivate-access-keys", "attach-deny-all-policy"} {
		if _, err := ParseAction(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"", "delete-user", "terminate-instances"} {
		if _, err := ParseAction(a); !errors.Is(err, ErrRefused) {
			t.Errorf("%q must be refused", a)
		}
	}
}
