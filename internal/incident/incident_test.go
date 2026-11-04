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

func (h *harness) appendAt(kind, id string, data any, at time.Time) evidence.Record {
	h.t.Helper()
	r, err := h.log.Append(kind, id, data, at)
	if err != nil {
		h.t.Fatal(err)
	}
	h.recs = append(h.recs, r)
	return r
}

func (h *harness) findingRequiring(id string, required int) evidence.Record {
	return h.append(KindFinding, id, FindingData{
		Finding:           detect.Finding{Principal: principal, Confidence: 95},
		Decision:          &policy.Decision{Action: policy.RecommendContainment, EligibleForContainment: true},
		ApprovalsRequired: required,
	})
}

var bob = Decider{Operator: "bob", RecordedBy: "bob-laptop", Reason: "agree, key is stolen"}

func (h *harness) approve(req ApproveRequest, at time.Time) evidence.Record {
	h.t.Helper()
	ap, err := Approve(h.recs, req, at)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.appendAt(KindApproval, req.IncidentID, ap, at)
}

func TestLifecycleTwoPersonRule(t *testing.T) {
	h := newHarness(t)
	f := h.finding("inc_a", true, 98.6)
	if s := h.state("inc_a", t0); s.State != StatePending || s.FindingRecord != f.Hash || s.RequiredApprovals != 2 {
		t.Fatalf("want pending needing 2, got %+v", s)
	}

	first := h.approve(approveReq("inc_a"), t0)
	if s := h.state("inc_a", t0); s.State != StatePartiallyApproved || len(s.Approvals) != 1 || s.Action != DeactivateAccessKeys {
		t.Fatalf("one approval must be partial, got %+v", s)
	}

	// The same person, or the same OS account under another name, cannot complete the quorum.
	if _, err := Approve(h.recs, approveReq("inc_a"), t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "different operator") {
		t.Fatalf("same operator: %v", err)
	}
	sameAccount := approveReq("inc_a")
	sameAccount.Operator = "mallory"
	if _, err := Approve(h.recs, sameAccount, t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "another account") {
		t.Fatalf("same OS account: %v", err)
	}
	otherAction := approveReq("inc_a")
	otherAction.Decider, otherAction.Action = bob, AttachDenyAllPolicy
	if _, err := Approve(h.recs, otherAction, t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "approve that action") {
		t.Fatalf("different action: %v", err)
	}

	second := approveReq("inc_a")
	second.Decider, second.TTL = bob, time.Hour
	secondRec := h.approve(second, t0.Add(10*time.Minute))
	s := h.state("inc_a", t0.Add(20*time.Minute))
	if s.State != StateApproved || len(s.Approvals) != 2 || s.ApprovalRecords[0] != first.Hash {
		t.Fatalf("two distinct approvals must approve, got %+v", s)
	}
	// The quorum expires with its earliest approval: bob's 1h from t0+10m.
	if !s.ExpiresAt.Equal(t0.Add(70 * time.Minute)) {
		t.Fatalf("round expiry %v, want earliest approval's", s.ExpiresAt)
	}
	if st := h.state("inc_a", t0.Add(70*time.Minute)); st.State != StateExpired {
		t.Fatalf("want expired at the earliest deadline, got %s", st.State)
	}

	third := approveReq("inc_a")
	third.Decider = Decider{Operator: "carol", RecordedBy: "carol-laptop", Reason: "r"}
	if _, err := Approve(h.recs, third, t0.Add(20*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("approving an approved incident: %v", err)
	}
	if _, err := Reject(h.recs, "inc_a", op, t0.Add(20*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("rejecting an approved incident must require revoking first: %v", err)
	}

	// One operator can revoke the whole round.
	rv, err := Revoke(h.recs, "inc_a", op, t0.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rv.ApprovalRecord != secondRec.Hash {
		t.Fatalf("revocation must reference the round: %+v", rv)
	}
	h.appendAt(KindRevocation, "inc_a", rv, t0.Add(20*time.Minute))
	if st := h.state("inc_a", t0.Add(20*time.Minute)); st.State != StateRevoked || len(st.Approvals) != 0 {
		t.Fatalf("want revoked, got %+v", st)
	}
	if _, err := Revoke(h.recs, "inc_a", op, t0.Add(20*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoking twice: %v", err)
	}

	// A new round after revocation; one operator can reject it while partial.
	h.approve(approveReq("inc_a"), t0.Add(30*time.Minute))
	if st := h.state("inc_a", t0.Add(30*time.Minute)); st.State != StatePartiallyApproved || len(st.Approvals) != 1 {
		t.Fatalf("approval after revocation must start a new round: %+v", st)
	}
	rj, err := Reject(h.recs, "inc_a", bob, t0.Add(31*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	h.appendAt(KindRejection, "inc_a", rj, t0.Add(31*time.Minute))
	if st := h.state("inc_a", t0.Add(31*time.Minute)); st.State != StateRejected || st.DecisionRecord == "" {
		t.Fatalf("want rejected, got %+v", st)
	}
	if _, err := Approve(h.recs, second, t0.Add(32*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("approving a rejected finding: %v", err)
	}

	// A newer finding needs fresh decisions.
	f2 := h.finding("inc_a", true, 99)
	if st := h.state("inc_a", t0); st.State != StatePending || st.FindingRecord != f2.Hash {
		t.Fatalf("newer finding must reset to pending: %+v", st)
	}
}

func TestQuorumOfOne(t *testing.T) {
	h := newHarness(t)
	h.findingRequiring("inc_solo", 1)
	h.approve(approveReq("inc_solo"), t0)
	if s := h.state("inc_solo", t0); s.State != StateApproved || s.RequiredApprovals != 1 {
		t.Fatalf("quorum of one must approve with one operator: %+v", s)
	}
}

func TestQuorumOfThree(t *testing.T) {
	h := newHarness(t)
	h.findingRequiring("inc_3", 3)
	h.approve(approveReq("inc_3"), t0)
	r2 := approveReq("inc_3")
	r2.Decider = bob
	h.approve(r2, t0)
	if s := h.state("inc_3", t0); s.State != StatePartiallyApproved {
		t.Fatalf("two of three must stay partial: %s", s.State)
	}
	r3 := approveReq("inc_3")
	r3.Decider = Decider{Operator: "carol", Reason: "r"} // no OS account recorded
	h.approve(r3, t0)
	if s := h.state("inc_3", t0); s.State != StateApproved || len(s.Approvals) != 3 {
		t.Fatalf("three distinct operators must approve: %+v", s)
	}
}

func TestPartialRoundExpires(t *testing.T) {
	h := newHarness(t)
	h.finding("inc_a", true, 90)
	short := approveReq("inc_a")
	short.TTL = time.Hour
	h.approve(short, t0)
	if s := h.state("inc_a", t0.Add(time.Hour)); s.State != StateExpired {
		t.Fatalf("partial round must expire: %s", s.State)
	}
	// An approval after expiry starts a fresh round instead of completing the old one.
	late := approveReq("inc_a")
	late.Decider = bob
	h.approve(late, t0.Add(2*time.Hour))
	s := h.state("inc_a", t0.Add(2*time.Hour))
	if s.State != StatePartiallyApproved || len(s.Approvals) != 1 || s.Approvals[0].Operator != "bob" {
		t.Fatalf("late approval must not join an expired round: %+v", s)
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
	if st := h.state("inc_ok", t0); st.State != StateRejected {
		t.Fatalf("want rejected, got %s", st.State)
	}
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
	for _, kind := range []string{KindFinding, KindApproval, KindRejection, KindRevocation} {
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
