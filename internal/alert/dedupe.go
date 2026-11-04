package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ErrState is wrapped by state-file errors.
var ErrState = errors.New("invalid alert state")

const stateVersion = 1

// StateRetention is how long sent-alert records are kept.
const StateRetention = 30 * 24 * time.Hour

// Verdict says whether an alert should be sent given earlier sends.
type Verdict string

const (
	// VerdictNew: no earlier alert covers this finding.
	VerdictNew Verdict = "new"
	// VerdictEscalated: confidence rose or the decision changed since the last send.
	VerdictEscalated Verdict = "escalated"
	// VerdictReminder: unchanged, but the suppression period has passed.
	VerdictReminder Verdict = "reminder"
	// VerdictDuplicate: an equivalent alert was sent recently; do not send.
	VerdictDuplicate Verdict = "duplicate"
)

// StateEntry records one alert that was delivered.
type StateEntry struct {
	Principal  string    `json:"principal"`
	First      time.Time `json:"first_event_time"`
	Last       time.Time `json:"last_event_time"`
	Confidence float64   `json:"confidence"`
	Action     string    `json:"action,omitempty"`
	SentAt     time.Time `json:"sent_at"`
}

// State is the set of delivered alerts used for de-duplication.
// It assumes a single writer; concurrent runs sharing one file may both send.
type State struct {
	Version int          `json:"version"`
	Entries []StateEntry `json:"entries"`
}

// LoadState reads a state file. A missing file is an empty state; a
// malformed one is an error, so suppression never silently resets.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Version: stateVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrState, path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%w: %s: unsupported version %d", ErrState, path, s.Version)
	}
	return &s, nil
}

func action(a Alert) string {
	if a.Decision == nil {
		return ""
	}
	return string(a.Decision.Action)
}

// match returns the index of the most recent entry for the same principal
// whose time range overlaps the alert's, allowing a gap of up to window.
func (s *State) match(a Alert, window time.Duration) int {
	best := -1
	for i, e := range s.Entries {
		if e.Principal != a.Principal {
			continue
		}
		if a.First.After(e.Last.Add(window)) || a.Last.Before(e.First.Add(-window)) {
			continue
		}
		if best < 0 || e.SentAt.After(s.Entries[best].SentAt) {
			best = i
		}
	}
	return best
}

// Check decides whether to send an alert. window is the detector's
// correlation window; suppressFor is how long an unchanged alert stays quiet.
func (s *State) Check(a Alert, window, suppressFor time.Duration, now time.Time) Verdict {
	i := s.match(a, window)
	if i < 0 {
		return VerdictNew
	}
	e := s.Entries[i]
	switch {
	case a.Confidence > e.Confidence || action(a) != e.Action:
		return VerdictEscalated
	case now.Sub(e.SentAt) >= suppressFor:
		return VerdictReminder
	default:
		return VerdictDuplicate
	}
}

// Record notes that an alert was delivered, merging it into a matching entry.
func (s *State) Record(a Alert, window time.Duration, now time.Time) {
	entry := StateEntry{Principal: a.Principal, First: a.First, Last: a.Last, Confidence: a.Confidence, Action: action(a), SentAt: now.UTC()}
	if i := s.match(a, window); i >= 0 {
		e := s.Entries[i]
		if e.First.Before(entry.First) {
			entry.First = e.First
		}
		if e.Last.After(entry.Last) {
			entry.Last = e.Last
		}
		s.Entries[i] = entry
		return
	}
	s.Entries = append(s.Entries, entry)
}

// Save prunes entries older than StateRetention and writes the state
// atomically with owner-only permissions.
func (s *State) Save(path string, now time.Time) error {
	kept := s.Entries[:0]
	for _, e := range s.Entries {
		if now.Sub(e.SentAt) < StateRetention {
			kept = append(kept, e)
		}
	}
	s.Entries, s.Version = kept, stateVersion
	if s.Entries == nil {
		s.Entries = []StateEntry{}
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cad-alert-state-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	return nil
}
