package incident

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

type operator struct {
	name string
	key  ed25519.PrivateKey
}

// newOperators generates keys and loads them back through the file formats.
func newOperators(t *testing.T, names ...string) (Operators, map[string]operator) {
	t.Helper()
	var entries []OperatorEntry
	byName := map[string]operator{}
	for _, n := range names {
		kf, entry, err := GenerateKey(n)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(kf)
		who, key, err := LoadKey(bytes.NewReader(raw))
		if err != nil || who != n {
			t.Fatalf("key round trip: %q %v", who, err)
		}
		entries = append(entries, entry)
		byName[n] = operator{n, key}
	}
	raw, _ := json.Marshal(operatorsFile{Operators: entries})
	ops, err := LoadOperators(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ops, byName
}

func signedFinding(h *harness, id string) {
	h.append(KindFinding, id, FindingData{
		Finding:                detect.Finding{Principal: principal, Confidence: 95},
		Decision:               &policy.Decision{Action: policy.RecommendContainment, EligibleForContainment: true},
		RequireSignedApprovals: true,
	})
}

func signedReq(id string, op operator) ApproveRequest {
	r := approveReq(id)
	r.Decider = Decider{Operator: op.name, RecordedBy: "shared-bastion", Reason: "confirmed"}
	r.Signer = op.key
	return r
}

func TestSignedApprovalQuorum(t *testing.T) {
	ops, keys := newOperators(t, "alice", "bob", "mallory")
	rv := Reviewer{Operators: ops}
	h := newHarness(t)
	signedFinding(h, "inc_s")

	ap, err := rv.Approve(h.recs, signedReq("inc_s", keys["alice"]), t0)
	if err != nil || ap.Signature == "" {
		t.Fatalf("signed approval: %+v %v", ap, err)
	}
	h.append(KindApproval, "inc_s", ap)
	if s, _ := rv.StatusOf(h.recs, "inc_s", t0); s.State != StatePartiallyApproved || !s.SignedApprovalsRequired {
		t.Fatalf("want partial, got %+v", s)
	}
	// The second approver uses the same OS account; with signatures that is allowed.
	ap2, err := rv.Approve(h.recs, signedReq("inc_s", keys["bob"]), t0)
	if err != nil {
		t.Fatal(err)
	}
	h.append(KindApproval, "inc_s", ap2)
	if s, _ := rv.StatusOf(h.recs, "inc_s", t0); s.State != StateApproved || s.UnverifiedApprovals != 0 {
		t.Fatalf("want approved, got %+v", s)
	}
	// Without the trusted keys nothing verifies, so nothing counts.
	if s, _ := StatusOf(h.recs, "inc_s", t0); s.State != StatePending || s.UnverifiedApprovals != 2 {
		t.Fatalf("without operators: %+v", s)
	}
}

func TestSignedApprovalRefusals(t *testing.T) {
	ops, keys := newOperators(t, "alice", "bob")
	_, outsiders := newOperators(t, "eve")
	rv := Reviewer{Operators: ops}
	h := newHarness(t)
	signedFinding(h, "inc_s")

	unsigned := signedReq("inc_s", keys["alice"])
	unsigned.Signer = nil
	if _, err := rv.Approve(h.recs, unsigned, t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "sign with") {
		t.Fatalf("unsigned: %v", err)
	}
	if _, err := rv.Approve(h.recs, signedReq("inc_s", outsiders["eve"]), t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not in the trusted operators") {
		t.Fatalf("untrusted operator: %v", err)
	}
	// Bob's key claiming to be Alice.
	impostor := signedReq("inc_s", keys["alice"])
	impostor.Signer = keys["bob"].key
	if _, err := rv.Approve(h.recs, impostor, t0); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not the trusted key") {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := (Reviewer{}).Approve(h.recs, signedReq("inc_s", keys["alice"]), t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("no operators loaded: %v", err)
	}
}

// Records written straight into the log, bypassing Approve, must not count.
func TestForgedAndTamperedApprovalsIgnored(t *testing.T) {
	ops, keys := newOperators(t, "alice", "bob")
	rv := Reviewer{Operators: ops}
	h := newHarness(t)
	signedFinding(h, "inc_s")
	good, err := rv.Approve(h.recs, signedReq("inc_s", keys["alice"]), t0)
	if err != nil {
		t.Fatal(err)
	}

	forged := good
	forged.Operator, forged.Signature = "bob", "" // unsigned claim
	h.append(KindApproval, "inc_s", forged)
	reused := good
	reused.Operator = "bob" // Alice's signature under Bob's name
	h.append(KindApproval, "inc_s", reused)
	widened := good
	widened.Action = AttachDenyAllPolicy // signed content changed
	h.append(KindApproval, "inc_s", widened)
	extended := good
	extended.ExpiresAt = good.ExpiresAt.Add(24 * time.Hour)
	h.append(KindApproval, "inc_s", extended)
	garbage := good
	garbage.Signature = "!!not base64!!"
	h.append(KindApproval, "inc_s", garbage)

	s, err := rv.StatusOf(h.recs, "inc_s", t0)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != StatePending || s.UnverifiedApprovals != 5 || len(s.Approvals) != 0 {
		t.Fatalf("forged approvals must not count: %+v", s)
	}
	h.append(KindApproval, "inc_s", good)
	if s, _ := rv.StatusOf(h.recs, "inc_s", t0); s.State != StatePartiallyApproved || len(s.Approvals) != 1 {
		t.Fatalf("the genuine approval must count: %+v", s)
	}
}

func TestSignatureOptionalWhenNotRequired(t *testing.T) {
	_, keys := newOperators(t, "alice")
	h := newHarness(t)
	h.finding("inc_a", true, 90)
	ap, err := Approve(h.recs, signedReq("inc_a", keys["alice"]), t0)
	if err != nil || ap.Signature == "" {
		t.Fatalf("optional signature: %+v %v", ap, err)
	}
	h.append(KindApproval, "inc_a", ap)
	if s := h.state("inc_a", t0); s.State != StatePartiallyApproved || s.SignedApprovalsRequired {
		t.Fatalf("unsigned-mode finding: %+v", s)
	}
}

func TestLoadOperatorsAndKeysReject(t *testing.T) {
	_, e1, _ := GenerateKey("alice")
	_, e2, _ := GenerateKey("bob")
	file := func(entries ...OperatorEntry) string {
		raw, _ := json.Marshal(operatorsFile{Operators: entries})
		return string(raw)
	}
	for name, doc := range map[string]string{
		"not json":      `nope`,
		"empty":         `{"operators":[]}`,
		"unknown field": `{"operators":[],"x":1}`,
		"bad key":       file(OperatorEntry{Name: "alice", PublicKey: "AAAA"}),
		"no name":       file(OperatorEntry{Name: " ", PublicKey: e1.PublicKey}),
		"dup name":      file(e1, OperatorEntry{Name: "alice", PublicKey: e2.PublicKey}),
		"dup key":       file(e1, OperatorEntry{Name: "carol", PublicKey: e1.PublicKey}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadOperators(strings.NewReader(doc)); !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
		})
	}
	for name, doc := range map[string]string{
		"not json":    `PRIVATE-MATERIAL`,
		"short key":   `{"operator":"a","private_key":"AAAA"}`,
		"no operator": `{"operator":"","private_key":"` + strings.Repeat("A", 88) + `"}`,
	} {
		t.Run("key "+name, func(t *testing.T) {
			_, _, err := LoadKey(strings.NewReader(doc))
			if !errors.Is(err, ErrRefused) || strings.Contains(err.Error(), "PRIVATE-MATERIAL") {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, _, err := GenerateKey(" "); !errors.Is(err, ErrRefused) {
		t.Fatalf("empty operator: %v", err)
	}
	if _, err := SignApproval(ApprovalData{}, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("nil key: %v", err)
	}
}
