// Package cloudtrail reads AWS CloudTrail log files offline and normalizes
// records into minimal, redacted events tagged with explainable indicators.
//
// It makes no AWS API calls. Input is the S3 delivery format
// ({"Records": [...]}), optionally gzip-compressed.
//
// Normalized events deliberately drop raw request and response payloads:
// only the few fields the indicators need are extracted, and access key IDs
// are masked. Indicators are signals for a detector to weigh, not verdicts.
package cloudtrail

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ErrInvalid is wrapped by every parse or validation error in this package.
var ErrInvalid = errors.New("invalid cloudtrail input")

// MaxDecodedBytes caps how much (decompressed) log data one Parse call reads,
// so a malformed or hostile gzip file cannot exhaust memory.
const MaxDecodedBytes = 256 << 20

// maxDecodedBytes is the limit actually enforced; tests lower it.
var maxDecodedBytes int64 = MaxDecodedBytes

const maxUserAgentLen = 256

// UserIdentity is the subset of CloudTrail's userIdentity the adapter uses.
type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	AccessKeyID string `json:"accessKeyId"`
	InvokedBy   string `json:"invokedBy"`
}

// Record is the subset of a raw CloudTrail record the adapter uses.
// Unknown fields are ignored, since CloudTrail adds fields over time.
type Record struct {
	EventVersion       string          `json:"eventVersion"`
	EventTime          time.Time       `json:"eventTime"`
	EventSource        string          `json:"eventSource"`
	EventName          string          `json:"eventName"`
	AWSRegion          string          `json:"awsRegion"`
	SourceIPAddress    string          `json:"sourceIPAddress"`
	UserAgent          string          `json:"userAgent"`
	ErrorCode          string          `json:"errorCode"`
	EventID            string          `json:"eventID"`
	RecipientAccountID string          `json:"recipientAccountId"`
	UserIdentity       UserIdentity    `json:"userIdentity"`
	RequestParameters  json.RawMessage `json:"requestParameters"`
}

// Indicator is a named, explainable signal attached to an event.
type Indicator string

const (
	// GPUInstanceLaunch: RunInstances for an accelerated (GPU/ML) instance family,
	// a common cryptojacking and model-abuse step.
	GPUInstanceLaunch Indicator = "gpu_instance_launch"
	// BulkInstanceLaunch: one RunInstances call requesting many instances.
	BulkInstanceLaunch Indicator = "bulk_instance_launch"
	// QuotaIncreaseRequest: a service quota increase, often requested before mass launches.
	QuotaIncreaseRequest Indicator = "quota_increase_request"
	// MonitoringTampering: CloudTrail or GuardDuty being stopped, deleted or reconfigured.
	MonitoringTampering Indicator = "monitoring_tampering"
	// BedrockLoggingDisabled: Bedrock model invocation logging removed.
	BedrockLoggingDisabled Indicator = "bedrock_logging_disabled"
	// BedrockModelAccessChange: a request to enable access to foundation models.
	BedrockModelAccessChange Indicator = "bedrock_model_access_change"
	// CredentialCreation: new IAM users, access keys or console passwords.
	CredentialCreation Indicator = "credential_creation"
	// AccessDenied: a call rejected for lack of permission, typical of enumeration with stolen keys.
	AccessDenied Indicator = "access_denied"
	// RootActivity: a call made directly by the account root user.
	RootActivity Indicator = "root_activity"
	// AlternateComputeLaunch: compute started through ECS, Batch, SageMaker or
	// Lambda rather than EC2. Common in normal deployments, so it is weak
	// alone; it matters when combined with evasion or new credentials.
	AlternateComputeLaunch Indicator = "alternate_compute_launch"
	// PrivilegeEscalation: an administrator policy attached to a user, role or group.
	PrivilegeEscalation Indicator = "privilege_escalation"
)

// adminPolicySuffix identifies the AWS managed administrator policy in any partition.
const adminPolicySuffix = ":iam::aws:policy/AdministratorAccess"

// BulkInstanceThreshold is the requested instance count at or above which a
// single RunInstances call is tagged BulkInstanceLaunch.
const BulkInstanceThreshold = 10

// actionIndicators maps "service:EventName" to the indicator it carries.
var actionIndicators = map[string]Indicator{
	"cloudtrail:StopLogging":                            MonitoringTampering,
	"cloudtrail:DeleteTrail":                            MonitoringTampering,
	"cloudtrail:UpdateTrail":                            MonitoringTampering,
	"cloudtrail:PutEventSelectors":                      MonitoringTampering,
	"guardduty:DeleteDetector":                          MonitoringTampering,
	"guardduty:UpdateDetector":                          MonitoringTampering,
	"bedrock:DeleteModelInvocationLoggingConfiguration": BedrockLoggingDisabled,
	"bedrock:PutUseCaseForModelAccess":                  BedrockModelAccessChange,
	"bedrock:CreateFoundationModelAgreement":            BedrockModelAccessChange,
	"bedrock:PutFoundationModelEntitlement":             BedrockModelAccessChange,
	"iam:CreateAccessKey":                               CredentialCreation,
	"iam:CreateLoginProfile":                            CredentialCreation,
	"iam:UpdateLoginProfile":                            CredentialCreation,
	"iam:CreateUser":                                    CredentialCreation,
	"servicequotas:RequestServiceQuotaIncrease":         QuotaIncreaseRequest,
	"ecs:RunTask":                                       AlternateComputeLaunch,
	"ecs:CreateService":                                 AlternateComputeLaunch,
	"batch:SubmitJob":                                   AlternateComputeLaunch,
	"batch:CreateComputeEnvironment":                    AlternateComputeLaunch,
	"sagemaker:CreateNotebookInstance":                  AlternateComputeLaunch,
	"sagemaker:CreateTrainingJob":                       AlternateComputeLaunch,
	"sagemaker:CreateProcessingJob":                     AlternateComputeLaunch,
	"lambda:CreateFunction20150331":                     AlternateComputeLaunch,
}

// attachPolicyActions are the IAM calls checked for an administrator policy.
var attachPolicyActions = map[string]bool{"AttachUserPolicy": true, "AttachRolePolicy": true, "AttachGroupPolicy": true}

// userTargetActions are the IAM calls whose target user is extracted, so the
// detector can follow an identity created or re-keyed by another principal.
var userTargetActions = map[string]bool{"CreateUser": true, "CreateAccessKey": true, "CreateLoginProfile": true, "UpdateLoginProfile": true}

const maxTargetUserLen = 128

var accessDeniedCodes = map[string]bool{
	"AccessDenied":                 true,
	"AccessDeniedException":        true,
	"UnauthorizedOperation":        true,
	"Client.UnauthorizedOperation": true,
}

// acceleratedFamilies are the instance-family letter prefixes treated as GPU/ML accelerated.
var acceleratedFamilies = map[string]bool{"p": true, "g": true, "inf": true, "trn": true, "dl": true}

// Event is a normalized, redacted CloudTrail event.
type Event struct {
	Time          time.Time `json:"time"`
	EventID       string    `json:"event_id"`
	Service       string    `json:"service"`
	Action        string    `json:"action"`
	Region        string    `json:"region"`
	AccountID     string    `json:"account_id,omitempty"`
	PrincipalType string    `json:"principal_type,omitempty"`
	PrincipalARN  string    `json:"principal_arn,omitempty"`
	AccessKeyID   string    `json:"access_key_id,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
	InstanceType  string    `json:"instance_type,omitempty"`
	InstanceCount int       `json:"instance_count,omitempty"`
	// TargetUser is the IAM user name a credential-creating call acted on.
	TargetUser string      `json:"target_user,omitempty"`
	Indicators []Indicator `json:"indicators,omitempty"`
}

// Summary aggregates a set of normalized events.
type Summary struct {
	Events         int               `json:"events"`
	WithIndicators int               `json:"events_with_indicators"`
	First          time.Time         `json:"first_event_time"`
	Last           time.Time         `json:"last_event_time"`
	ByIndicator    map[Indicator]int `json:"by_indicator"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parse reads one CloudTrail log file ({"Records": [...]}), transparently
// decompressing gzip input, and validates each record's required fields.
func Parse(r io.Reader) ([]Record, error) {
	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		defer gz.Close()
		src = gz
	}
	limited := &io.LimitedReader{R: src, N: maxDecodedBytes + 1}

	var doc struct {
		Records *[]Record `json:"Records"`
	}
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&doc); err != nil {
		if limited.N <= 0 {
			return nil, invalid("log exceeds %d decoded bytes", maxDecodedBytes)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, invalid("unexpected data after JSON document")
	}
	if doc.Records == nil {
		return nil, invalid(`missing "Records" array`)
	}
	for i, rec := range *doc.Records {
		switch {
		case rec.EventTime.IsZero():
			return nil, invalid("record %d: missing eventTime", i)
		case rec.EventSource == "":
			return nil, invalid("record %d: missing eventSource", i)
		case rec.EventName == "":
			return nil, invalid("record %d: missing eventName", i)
		case rec.EventID == "":
			return nil, invalid("record %d: missing eventID", i)
		}
	}
	return *doc.Records, nil
}

// MaskAccessKeyID keeps the 4-character type prefix and last 4 characters.
func MaskAccessKeyID(id string) string {
	if len(id) <= 8 {
		return strings.Repeat("*", len(id))
	}
	return id[:4] + strings.Repeat("*", len(id)-8) + id[len(id)-4:]
}

func serviceName(eventSource string) string {
	return strings.TrimSuffix(eventSource, ".amazonaws.com")
}

func accelerated(instanceType string) bool {
	family, _, _ := strings.Cut(instanceType, ".")
	i := 0
	for i < len(family) && family[i] >= 'a' && family[i] <= 'z' {
		i++
	}
	return acceleratedFamilies[family[:i]]
}

type runInstancesParams struct {
	InstanceType string `json:"instanceType"`
	InstancesSet struct {
		Items []struct {
			MinCount int `json:"minCount"`
			MaxCount int `json:"maxCount"`
		} `json:"items"`
	} `json:"instancesSet"`
}

// Normalize converts one record into a redacted event with indicators.
func Normalize(rec Record) Event {
	ev := Event{
		Time:          rec.EventTime.UTC(),
		EventID:       rec.EventID,
		Service:       serviceName(rec.EventSource),
		Action:        rec.EventName,
		Region:        rec.AWSRegion,
		AccountID:     rec.RecipientAccountID,
		PrincipalType: rec.UserIdentity.Type,
		PrincipalARN:  rec.UserIdentity.ARN,
		SourceIP:      rec.SourceIPAddress,
		UserAgent:     rec.UserAgent,
		ErrorCode:     rec.ErrorCode,
	}
	if ev.AccountID == "" {
		ev.AccountID = rec.UserIdentity.AccountID
	}
	if rec.UserIdentity.AccessKeyID != "" {
		ev.AccessKeyID = MaskAccessKeyID(rec.UserIdentity.AccessKeyID)
	}
	if len(ev.UserAgent) > maxUserAgentLen {
		ev.UserAgent = ev.UserAgent[:maxUserAgentLen]
	}

	add := func(ind Indicator) {
		for _, have := range ev.Indicators {
			if have == ind {
				return
			}
		}
		ev.Indicators = append(ev.Indicators, ind)
	}

	if ev.Service == "ec2" && ev.Action == "RunInstances" {
		var p runInstancesParams
		// Malformed parameters are ignored; the event is still reported.
		if json.Unmarshal(rec.RequestParameters, &p) == nil {
			ev.InstanceType = p.InstanceType
			for _, it := range p.InstancesSet.Items {
				n := it.MaxCount
				if n < it.MinCount {
					n = it.MinCount
				}
				if n > 0 {
					ev.InstanceCount += n
				}
			}
		}
		if accelerated(ev.InstanceType) {
			add(GPUInstanceLaunch)
		}
		if ev.InstanceCount >= BulkInstanceThreshold {
			add(BulkInstanceLaunch)
		}
	}
	if ev.Service == "sagemaker" {
		// SageMaker types look like "ml.p3.2xlarge"; only the type is read.
		var p struct {
			InstanceType   string `json:"instanceType"`
			ResourceConfig struct {
				InstanceType string `json:"instanceType"`
			} `json:"resourceConfig"`
		}
		if json.Unmarshal(rec.RequestParameters, &p) == nil {
			t := p.InstanceType
			if t == "" {
				t = p.ResourceConfig.InstanceType
			}
			if accelerated(strings.TrimPrefix(t, "ml.")) {
				ev.InstanceType = t
				add(GPUInstanceLaunch)
			}
		}
	}
	if ev.Service == "iam" && (attachPolicyActions[ev.Action] || userTargetActions[ev.Action]) {
		var p struct {
			UserName  string `json:"userName"`
			PolicyARN string `json:"policyArn"`
		}
		if json.Unmarshal(rec.RequestParameters, &p) == nil {
			if userTargetActions[ev.Action] && len(p.UserName) <= maxTargetUserLen {
				ev.TargetUser = p.UserName
			}
			if attachPolicyActions[ev.Action] && strings.HasSuffix(p.PolicyARN, adminPolicySuffix) {
				add(PrivilegeEscalation)
			}
		}
	}
	if ind, ok := actionIndicators[ev.Service+":"+ev.Action]; ok {
		add(ind)
	}
	if accessDeniedCodes[rec.ErrorCode] {
		add(AccessDenied)
	}
	if rec.UserIdentity.Type == "Root" && rec.UserIdentity.InvokedBy == "" {
		add(RootActivity)
	}
	return ev
}

// Replay parses a log file and returns normalized events in a deterministic
// order (event time, then event ID).
func Replay(r io.Reader) ([]Event, error) {
	recs, err := Parse(r)
	if err != nil {
		return nil, err
	}
	events := make([]Event, len(recs))
	for i, rec := range recs {
		events[i] = Normalize(rec)
	}
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].Time.Equal(events[j].Time) {
			return events[i].Time.Before(events[j].Time)
		}
		return events[i].EventID < events[j].EventID
	})
	return events, nil
}

// Summarize counts events and indicators. Events are assumed sorted, as Replay returns them.
func Summarize(events []Event) Summary {
	s := Summary{Events: len(events), ByIndicator: map[Indicator]int{}}
	if len(events) > 0 {
		s.First, s.Last = events[0].Time, events[len(events)-1].Time
	}
	for _, ev := range events {
		if len(ev.Indicators) > 0 {
			s.WithIndicators++
		}
		for _, ind := range ev.Indicators {
			s.ByIndicator[ind]++
		}
	}
	return s
}
