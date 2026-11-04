// Package incident defines the evidence-log record types and the operator
// approval workflow for containment.
//
// Approvals are records, not actions: nothing in this project executes
// containment. An approval states that a named operator authorised one
// reversible action against the principal of one specific finding record,
// until an expiry. Approval is never inferred from a score; it is only ever
// a recorded human decision on a finding the policy marked eligible.
//
// Decisions bind to the finding record they were made on. When a later run
// records a newer finding for the same incident, the incident returns to
// pending and needs a fresh decision.
package incident

import (
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
	StateNotEligible State = "not_eligible" // latest finding is not containment eligible
	StatePending     State = "pending"      // eligible, no decision on the latest finding
	StateApproved    State = "approved"     // an unexpired, unrevoked approval exists
	StateRejected    State = "rejected"
	StateExpired     State = "expired"
	StateRevoked     State = "revoked"
)

// Status summarises one incident.
type Status struct {
	IncidentID    string           `json:"incident_id"`
	Principal     string           `json:"principal"`
	State         State            `json:"state"`
	Confidence    float64          `json:"confidence"`
	Decision      *policy.Decision `json:"decision,omitempty"`
	FindingRecord string           `json:"finding_record"`
	// DecisionRecord is the approval or rejection record behind State, if any.
	DecisionRecord string        `json:"decision_record,omitempty"`
	Approval       *ApprovalData `json:"approval,omitempty"`
}

type incidentRecords struct {
	finding     evidence.Record
	findingData FindingData
	decision    *evidence.Record // latest approval or rejection on the latest finding
	revoked     map[string]bool  // approval record hash -> revoked
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
			ir := byID[rec.IncidentID]
			if ir == nil {
				ir = &incidentRecords{revoked: map[string]bool{}}
				byID[rec.IncidentID] = ir
			}
			// A newer finding resets the decision.
			ir.finding, ir.findingData, ir.decision = rec, fd, nil
		case KindApproval, KindRejection:
			ir := byID[rec.IncidentID]
			if ir == nil {
				continue
			}
			var link struct {
				FindingRecord string `json:"finding_record"`
			}
			if err := decode(rec, &link); err != nil {
				return nil, err
			}
			if link.FindingRecord == ir.finding.Hash {
				r := rec
				ir.decision = &r
			}
		case KindRevocation:
			ir := byID[rec.IncidentID]
			if ir == nil {
				continue
			}
			var rv RevocationData
			if err := decode(rec, &rv); err != nil {
				return nil, err
			}
			ir.revoked[rv.ApprovalRecord] = true
		}
	}
	return byID, nil
}

func status(id string, ir *incidentRecords, now time.Time) (Status, error) {
	s := Status{
		IncidentID:    id,
		Principal:     ir.findingData.Finding.Principal,
		Confidence:    ir.findingData.Finding.Confidence,
		Decision:      ir.findingData.Decision,
		FindingRecord: ir.finding.Hash,
	}
	if d := ir.findingData.Decision; d == nil || !d.EligibleForContainment {
		s.State = StateNotEligible
		return s, nil
	}
	if ir.decision == nil {
		s.State = StatePending
		return s, nil
	}
	s.DecisionRecord = ir.decision.Hash
	if ir.decision.Kind == KindRejection {
		s.State = StateRejected
		return s, nil
	}
	var ap ApprovalData
	if err := decode(*ir.decision, &ap); err != nil {
		return s, err
	}
	s.Approval = &ap
	switch {
	case ir.revoked[ir.decision.Hash]:
		s.State = StateRevoked
	case !now.Before(ap.ExpiresAt):
		s.State = StateExpired
	default:
		s.State = StateApproved
	}
	return s, nil
}

// Summarize returns the status of every incident in the log, ordered by incident ID.
func Summarize(records []evidence.Record, now time.Time) ([]Status, error) {
	byID, err := index(records)
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(byID))
	for id, ir := range byID {
		s, err := status(id, ir, now)
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
	byID, err := index(records)
	if err != nil {
		return Status{}, err
	}
	ir, ok := byID[id]
	if !ok {
		return Status{}, fmt.Errorf("%w: no finding recorded for incident %q", ErrRefused, id)
	}
	return status(id, ir, now)
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
}

// Approve validates the request against the incident's current state and
// returns the approval data to append.
func Approve(records []evidence.Record, req ApproveRequest, now time.Time) (ApprovalData, error) {
	if err := req.validate(); err != nil {
		return ApprovalData{}, err
	}
	if _, err := ParseAction(string(req.Action)); err != nil {
		return ApprovalData{}, err
	}
	if req.TTL <= 0 || req.TTL > MaxApprovalTTL {
		return ApprovalData{}, fmt.Errorf("%w: expiry must be greater than 0 and at most %s", ErrRefused, MaxApprovalTTL)
	}
	s, err := StatusOf(records, req.IncidentID, now)
	if err != nil {
		return ApprovalData{}, err
	}
	if req.Principal != s.Principal {
		return ApprovalData{}, fmt.Errorf("%w: principal %q does not match incident %s (%s)", ErrRefused, req.Principal, req.IncidentID, s.Principal)
	}
	switch s.State {
	case StatePending, StateExpired, StateRevoked:
	case StateNotEligible:
		return ApprovalData{}, fmt.Errorf("%w: incident %s is not containment eligible under the policy", ErrRefused, req.IncidentID)
	default:
		return ApprovalData{}, fmt.Errorf("%w: incident %s is already %s; revoke it first or wait for a newer finding", ErrRefused, req.IncidentID, s.State)
	}
	return ApprovalData{
		Decider:       req.Decider,
		Action:        req.Action,
		Principal:     s.Principal,
		FindingRecord: s.FindingRecord,
		ExpiresAt:     now.UTC().Add(req.TTL),
	}, nil
}

// Reject validates a rejection of the incident's latest finding.
func Reject(records []evidence.Record, id string, d Decider, now time.Time) (RejectionData, error) {
	if err := d.validate(); err != nil {
		return RejectionData{}, err
	}
	s, err := StatusOf(records, id, now)
	if err != nil {
		return RejectionData{}, err
	}
	switch s.State {
	case StatePending, StateExpired, StateRevoked:
	case StateNotEligible:
		return RejectionData{}, fmt.Errorf("%w: incident %s is not containment eligible; there is nothing to reject", ErrRefused, id)
	default:
		return RejectionData{}, fmt.Errorf("%w: incident %s is already %s", ErrRefused, id, s.State)
	}
	return RejectionData{Decider: d, FindingRecord: s.FindingRecord}, nil
}

// Revoke validates withdrawing the incident's active approval.
func Revoke(records []evidence.Record, id string, d Decider, now time.Time) (RevocationData, error) {
	if err := d.validate(); err != nil {
		return RevocationData{}, err
	}
	s, err := StatusOf(records, id, now)
	if err != nil {
		return RevocationData{}, err
	}
	if s.State != StateApproved {
		return RevocationData{}, fmt.Errorf("%w: incident %s has no active approval (state %s)", ErrRefused, id, s.State)
	}
	return RevocationData{Decider: d, ApprovalRecord: s.DecisionRecord}, nil
}
