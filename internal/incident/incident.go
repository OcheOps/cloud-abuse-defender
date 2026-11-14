// Package incident defines the evidence-log record types and the operator
// approval workflow for containment.
//
// Approvals are records, not actions: nothing in this project executes
// containment. An approval states that a named operator authorised one
// reversible action against the principal of one specific finding record,
// until an expiry. Approval is never inferred from a score; it is only ever
// a recorded human decision on a finding the policy marked eligible.
//
// Approval needs a quorum of distinct operators (two by default), fixed in
// the finding record at detection time. A single operator can always reject
// or revoke: stopping is easy, authorising is not.
//
// Decisions bind to the finding record they were made on. When a later run
// records a newer finding for the same incident, the incident returns to
// pending and needs a fresh decision.
package incident

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

// ErrRefused is wrapped when a decision is not allowed in the incident's current state.
var ErrRefused = errors.New("decision refused")

// Record kinds in the evidence log.
const (
	KindFinding      = "finding"
	KindNotification = "notification"
	KindApproval     = "approval"
	KindRejection    = "rejection"
	KindRevocation   = "revocation"
)

// Action is a containment action an operator may approve. Only reversible
// actions scoped to the finding's principal are offered.
type Action string

const (
	// DeactivateAccessKeys sets the principal's access keys to inactive; they can be reactivated.
	DeactivateAccessKeys Action = "deactivate-access-keys"
	// AttachDenyAllPolicy attaches an explicit deny-all policy; detaching it restores access.
	AttachDenyAllPolicy Action = "attach-deny-all-policy"
)

// ParseAction validates an action name.
func ParseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case DeactivateAccessKeys, AttachDenyAllPolicy:
		return a, nil
	}
	return "", fmt.Errorf("%w: unknown action %q (want %q or %q)", ErrRefused, s, DeactivateAccessKeys, AttachDenyAllPolicy)
}

// DefaultRequiredApprovals is the two-person rule: the quorum used when a
// finding does not record one.
const DefaultRequiredApprovals = 2

// MaxRequiredApprovals caps the quorum a finding may require.
const MaxRequiredApprovals = 5

// MaxApprovalTTL caps how long an approval stays valid.
const MaxApprovalTTL = 24 * time.Hour

const (
	maxOperatorLen = 128
	maxReasonLen   = 500
)

// FindingData is the evidence record for one finding: everything needed to
// explain the decision later, including the versions that made it.
type FindingData struct {
	Finding          detect.Finding   `json:"finding"`
	Decision         *policy.Decision `json:"decision,omitempty"`
	PricingVersion   string           `json:"pricing_version,omitempty"`
	HourlyCostUSD    float64          `json:"hourly_cost_usd,omitempty"`
	ForecastWarnings []string         `json:"forecast_warnings,omitempty"`
	PolicyVersion    string           `json:"policy_version"`
	WeightsVersion   string           `json:"weights_version"`
	// ApprovalsRequired is how many distinct operators must approve
	// containment for this finding. It is fixed when the finding is
	// recorded, so approvers cannot lower it.
	ApprovalsRequired int `json:"approvals_required,omitempty"`
	// RequireSignedApprovals means an approval only counts when it carries a
	// valid signature from a trusted operator key. Like the quorum, it is
	// fixed when the finding is recorded.
	RequireSignedApprovals bool `json:"require_signed_approvals,omitempty"`
	// EC2PricingVersion and SuppressionsVersion identify the other inputs
	// behind the decision, when they were used.
	EC2PricingVersion   string `json:"ec2_pricing_version,omitempty"`
	SuppressionsVersion string `json:"suppressions_version,omitempty"`
}

// NotificationData records a delivery attempt. The webhook URL is never recorded.
type NotificationData struct {
	Format  alert.Format  `json:"format"`
	Status  string        `json:"status"`
	Verdict alert.Verdict `json:"verdict,omitempty"`
	Error   string        `json:"error,omitempty"`
	// FindingRecord is the hash of the finding record this notification is about.
	FindingRecord string `json:"finding_record,omitempty"`
}

// Decider identifies who made a decision. Operator is the name the operator
// gave; RecordedBy is the local OS account that ran the command. Neither is
// authenticated: they record a claim, not a verified identity.
type Decider struct {
	Operator   string `json:"operator"`
	RecordedBy string `json:"recorded_by,omitempty"`
	Reason     string `json:"reason"`
}

// ApprovalData authorises one action until ExpiresAt.
type ApprovalData struct {
	Decider
	Action        Action    `json:"action"`
	Principal     string    `json:"principal"`
	FindingRecord string    `json:"finding_record"`
	ExpiresAt     time.Time `json:"expires_at"`
	// Signature is the operator's Ed25519 signature over every other field,
	// base64-encoded. See SignApproval.
	Signature string `json:"signature,omitempty"`
}

// RejectionData declines containment for one finding record.
type RejectionData struct {
	Decider
	FindingRecord string `json:"finding_record"`
}

// RevocationData withdraws an approval before it expires.
type RevocationData struct {
	Decider
	ApprovalRecord string `json:"approval_record"`
}

// State is where an incident stands in the approval workflow.
type State string

const (
	StateNotEligible       State = "not_eligible"       // latest finding is not containment eligible
	StatePending           State = "pending"            // eligible, no decision on the latest finding
	StatePartiallyApproved State = "partially_approved" // fewer distinct approvers than required so far
	StateApproved          State = "approved"           // enough distinct, unexpired, unrevoked approvals
	StateRejected          State = "rejected"
	StateExpired           State = "expired"
	StateRevoked           State = "revoked"
)

// Status summarises one incident.
type Status struct {
	IncidentID        string           `json:"incident_id"`
	Principal         string           `json:"principal"`
	State             State            `json:"state"`
	Confidence        float64          `json:"confidence"`
	Decision          *policy.Decision `json:"decision,omitempty"`
	FindingRecord     string           `json:"finding_record"`
	RequiredApprovals int              `json:"required_approvals"`
	// Approvals are the current round's approvals, oldest first.
	Approvals []ApprovalData `json:"approvals,omitempty"`
	// ApprovalRecords are the hashes of those approval records.
	ApprovalRecords []string `json:"approval_records,omitempty"`
	// Action and ExpiresAt describe the current round: its action and the
	// earliest expiry among its approvals.
	Action    Action     `json:"action,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// DecisionRecord is the rejection or revocation behind those states.
	DecisionRecord string `json:"decision_record,omitempty"`
	// SignedApprovalsRequired mirrors the finding record. When it is set,
	// UnverifiedApprovals counts approvals that were ignored because their
	// signature is missing, invalid or from an operator who is not trusted.
	SignedApprovalsRequired bool `json:"signed_approvals_required,omitempty"`
	UnverifiedApprovals     int  `json:"unverified_approvals,omitempty"`
}

// Reviewer evaluates incidents against a set of trusted operator keys. The
// zero value trusts no keys, which is enough for findings that do not
// require signed approvals.
type Reviewer struct {
	Operators Operators
}

// requiredApprovals returns the quorum recorded with the finding. Findings
// recorded before the field existed default to DefaultRequiredApprovals.
func requiredApprovals(fd FindingData) int {
	if fd.ApprovalsRequired <= 0 {
		return DefaultRequiredApprovals
	}
	return fd.ApprovalsRequired
}

type incidentRecords struct {
	finding     evidence.Record
	findingData FindingData
	// decisions are approval, rejection and revocation records appended
	// after the latest finding record, in log order.
	decisions []evidence.Record
}

func decode(rec evidence.Record, v any) error {
	if err := json.Unmarshal(rec.Data, v); err != nil {
		return fmt.Errorf("evidence record %d (%s): %w", rec.Seq, rec.Kind, err)
	}
	return nil
}

func index(records []evidence.Record) (map[string]*incidentRecords, error) {
	byID := map[string]*incidentRecords{}
	for _, rec := range records {
		switch rec.Kind {
		case KindFinding:
			var fd FindingData
			if err := decode(rec, &fd); err != nil {
				return nil, err
			}
			// A newer finding needs fresh decisions.
			byID[rec.IncidentID] = &incidentRecords{finding: rec, findingData: fd}
		case KindApproval, KindRejection, KindRevocation:
			if ir := byID[rec.IncidentID]; ir != nil {
				ir.decisions = append(ir.decisions, rec)
			}
		}
	}
	return byID, nil
}

type round struct {
	approvals []ApprovalData
	hashes    []string
	expiresAt time.Time
}

func (r *round) reset() { *r = round{} }

func (r *round) contains(hash string) bool {
	for _, h := range r.hashes {
		if h == hash {
			return true
		}
	}
	return false
}

func (r *round) operators() int {
	seen := map[string]bool{}
	for _, a := range r.approvals {
		seen[a.Operator] = true
	}
	return len(seen)
}

func (rv Reviewer) status(id string, ir *incidentRecords, now time.Time) (Status, error) {
	s := Status{
		IncidentID:        id,
		Principal:         ir.findingData.Finding.Principal,
		Confidence:        ir.findingData.Finding.Confidence,
		Decision:          ir.findingData.Decision,
		FindingRecord:     ir.finding.Hash,
		RequiredApprovals: requiredApprovals(ir.findingData),

		SignedApprovalsRequired: ir.findingData.RequireSignedApprovals,
	}
	if d := ir.findingData.Decision; d == nil || !d.EligibleForContainment {
		s.State = StateNotEligible
		return s, nil
	}

	// Replay decisions in order. A rejection or revocation ends the current
	// round; an approval arriving after the round expired starts a new one.
	var cur round
	var last string // kind of the last decision that ended a round
	for _, rec := range ir.decisions {
		switch rec.Kind {
		case KindApproval:
			var ap ApprovalData
			if err := decode(rec, &ap); err != nil {
				return s, err
			}
			if ap.FindingRecord != ir.finding.Hash {
				continue
			}
			if s.SignedApprovalsRequired && !rv.Operators.verify(ap) {
				s.UnverifiedApprovals++
				continue
			}
			if len(cur.approvals) > 0 && !rec.Time.Before(cur.expiresAt) {
				cur.reset()
			}
			if len(cur.approvals) == 0 || ap.ExpiresAt.Before(cur.expiresAt) {
				cur.expiresAt = ap.ExpiresAt
			}
			cur.approvals = append(cur.approvals, ap)
			cur.hashes = append(cur.hashes, rec.Hash)
			last, s.DecisionRecord = "", ""
		case KindRejection:
			var rj RejectionData
			if err := decode(rec, &rj); err != nil {
				return s, err
			}
			if rj.FindingRecord != ir.finding.Hash {
				continue
			}
			cur.reset()
			last, s.DecisionRecord = KindRejection, rec.Hash
		case KindRevocation:
			var rv RevocationData
			if err := decode(rec, &rv); err != nil {
				return s, err
			}
			if !cur.contains(rv.ApprovalRecord) {
				continue
			}
			cur.reset()
			last, s.DecisionRecord = KindRevocation, rec.Hash
		}
	}

	switch {
	case len(cur.approvals) > 0:
		s.Approvals, s.ApprovalRecords = cur.approvals, cur.hashes
		s.Action = cur.approvals[0].Action
		exp := cur.expiresAt
		s.ExpiresAt = &exp
		switch {
		case !now.Before(cur.expiresAt):
			s.State = StateExpired
		case cur.operators() >= s.RequiredApprovals:
			s.State = StateApproved
		default:
			s.State = StatePartiallyApproved
		}
	case last == KindRejection:
		s.State = StateRejected
	case last == KindRevocation:
		s.State = StateRevoked
	default:
		s.State = StatePending
	}
	return s, nil
}

// Summarize returns the status of every incident in the log, ordered by incident ID.
func Summarize(records []evidence.Record, now time.Time) ([]Status, error) {
	return Reviewer{}.Summarize(records, now)
}

// Summarize returns the status of every incident in the log, ordered by incident ID.
func (rv Reviewer) Summarize(records []evidence.Record, now time.Time) ([]Status, error) {
	byID, err := index(records)
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(byID))
	for id, ir := range byID {
		s, err := rv.status(id, ir, now)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IncidentID < out[j].IncidentID })
	return out, nil
}

// StatusOf returns one incident's status.
func StatusOf(records []evidence.Record, id string, now time.Time) (Status, error) {
	return Reviewer{}.StatusOf(records, id, now)
}

// StatusOf returns one incident's status.
func (rv Reviewer) StatusOf(records []evidence.Record, id string, now time.Time) (Status, error) {
	byID, err := index(records)
	if err != nil {
		return Status{}, err
	}
	ir, ok := byID[id]
	if !ok {
		return Status{}, fmt.Errorf("%w: no finding recorded for incident %q", ErrRefused, id)
	}
	return rv.status(id, ir, now)
}

func validText(field, v string, max int) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%w: %s is required", ErrRefused, field)
	}
	if len(v) > max {
		return fmt.Errorf("%w: %s is longer than %d characters", ErrRefused, field, max)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains control characters", ErrRefused, field)
		}
	}
	return nil
}

func (d Decider) validate() error {
	if err := validText("operator", d.Operator, maxOperatorLen); err != nil {
		return err
	}
	return validText("reason", d.Reason, maxReasonLen)
}

// ApproveRequest asks to authorise one action.
type ApproveRequest struct {
	Decider
	IncidentID string
	// Principal must repeat the finding's principal exactly, so an operator
	// cannot approve the wrong incident by mistyping its ID.
	Principal string
	Action    Action
	TTL       time.Duration
	// Signer is the operator's private key. It is required when the finding
	// requires signed approvals, and must match the operator's trusted key.
	Signer ed25519.PrivateKey
}

// Approve validates the request against the incident's current state and
// returns the approval data to append. When the incident is partially
// approved, the request joins that round: it must name the same action and
// come from an operator, and OS account, not already in the round.
func Approve(records []evidence.Record, req ApproveRequest, now time.Time) (ApprovalData, error) {
	return Reviewer{}.Approve(records, req, now)
}

// Approve validates the request as the package-level Approve does, checking
// signatures against the reviewer's trusted operators.
func (rv Reviewer) Approve(records []evidence.Record, req ApproveRequest, now time.Time) (ApprovalData, error) {
	if err := req.validate(); err != nil {
		return ApprovalData{}, err
	}
	if _, err := ParseAction(string(req.Action)); err != nil {
		return ApprovalData{}, err
	}
	if req.TTL <= 0 || req.TTL > MaxApprovalTTL {
		return ApprovalData{}, fmt.Errorf("%w: expiry must be greater than 0 and at most %s", ErrRefused, MaxApprovalTTL)
	}
	s, err := rv.StatusOf(records, req.IncidentID, now)
	if err != nil {
		return ApprovalData{}, err
	}
	if s.SignedApprovalsRequired {
		pub, trusted := rv.Operators[req.Operator]
		switch {
		case !trusted:
			return ApprovalData{}, fmt.Errorf("%w: incident %s requires signed approvals and %q is not in the trusted operators file", ErrRefused, req.IncidentID, req.Operator)
		case req.Signer == nil:
			return ApprovalData{}, fmt.Errorf("%w: incident %s requires signed approvals; sign with the operator's key", ErrRefused, req.IncidentID)
		case !pub.Equal(req.Signer.Public()):
			return ApprovalData{}, fmt.Errorf("%w: the signing key is not the trusted key for operator %q", ErrRefused, req.Operator)
		}
	}
	if req.Principal != s.Principal {
		return ApprovalData{}, fmt.Errorf("%w: principal %q does not match incident %s (%s)", ErrRefused, req.Principal, req.IncidentID, s.Principal)
	}
	switch s.State {
	case StatePending, StateExpired, StateRevoked:
	case StatePartiallyApproved:
		if req.Action != s.Action {
			return ApprovalData{}, fmt.Errorf("%w: incident %s has a pending approval for %s; approve that action or revoke it", ErrRefused, req.IncidentID, s.Action)
		}
		for _, a := range s.Approvals {
			if a.Operator == req.Operator {
				return ApprovalData{}, fmt.Errorf("%w: %s already approved incident %s; a different operator must approve", ErrRefused, req.Operator, req.IncidentID)
			}
			// With signed approvals the key proves who approved, so a shared
			// OS account (a bastion, for example) is not a reason to refuse.
			if !s.SignedApprovalsRequired && a.RecordedBy != "" && a.RecordedBy == req.RecordedBy {
				return ApprovalData{}, fmt.Errorf("%w: OS account %s already recorded an approval for incident %s; the next approval must come from another account", ErrRefused, req.RecordedBy, req.IncidentID)
			}
		}
	case StateNotEligible:
		return ApprovalData{}, fmt.Errorf("%w: incident %s is not containment eligible under the policy", ErrRefused, req.IncidentID)
	default:
		return ApprovalData{}, fmt.Errorf("%w: incident %s is already %s; revoke it first or wait for a newer finding", ErrRefused, req.IncidentID, s.State)
	}
	data := ApprovalData{
		Decider:       req.Decider,
		Action:        req.Action,
		Principal:     s.Principal,
		FindingRecord: s.FindingRecord,
		ExpiresAt:     now.UTC().Add(req.TTL),
	}
	if req.Signer != nil {
		if data.Signature, err = SignApproval(data, req.Signer); err != nil {
			return ApprovalData{}, err
		}
	}
	return data, nil
}

// Reject validates a rejection of the incident's latest finding. One
// operator can reject, including while an approval round is incomplete.
func Reject(records []evidence.Record, id string, d Decider, now time.Time) (RejectionData, error) {
	return Reviewer{}.Reject(records, id, d, now)
}

// Reject validates a rejection. Rejections are never required to be signed:
// stopping containment must stay easy.
func (rv Reviewer) Reject(records []evidence.Record, id string, d Decider, now time.Time) (RejectionData, error) {
	if err := d.validate(); err != nil {
		return RejectionData{}, err
	}
	s, err := rv.StatusOf(records, id, now)
	if err != nil {
		return RejectionData{}, err
	}
	switch s.State {
	case StatePending, StatePartiallyApproved, StateExpired, StateRevoked:
	case StateNotEligible:
		return RejectionData{}, fmt.Errorf("%w: incident %s is not containment eligible; there is nothing to reject", ErrRefused, id)
	default:
		return RejectionData{}, fmt.Errorf("%w: incident %s is already %s", ErrRefused, id, s.State)
	}
	return RejectionData{Decider: d, FindingRecord: s.FindingRecord}, nil
}

// Revoke validates withdrawing the incident's current approval round, whether
// complete or partial. One operator can revoke.
func Revoke(records []evidence.Record, id string, d Decider, now time.Time) (RevocationData, error) {
	return Reviewer{}.Revoke(records, id, d, now)
}

// Revoke validates a revocation. Like rejections, revocations need no signature.
func (rv Reviewer) Revoke(records []evidence.Record, id string, d Decider, now time.Time) (RevocationData, error) {
	if err := d.validate(); err != nil {
		return RevocationData{}, err
	}
	s, err := rv.StatusOf(records, id, now)
	if err != nil {
		return RevocationData{}, err
	}
	if s.State != StateApproved && s.State != StatePartiallyApproved {
		return RevocationData{}, fmt.Errorf("%w: incident %s has no active approval (state %s)", ErrRefused, id, s.State)
	}
	return RevocationData{Decider: d, ApprovalRecord: s.ApprovalRecords[len(s.ApprovalRecords)-1]}, nil
}
