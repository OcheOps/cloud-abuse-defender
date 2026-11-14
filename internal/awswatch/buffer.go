package awswatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Buffer keeps recent CloudTrail events across polls, de-duplicated by event
// ID, so the detector sees activity that spans more than one poll. Events
// older than the horizon are dropped, and the newest Max events are kept.
type Buffer struct {
	Horizon time.Duration
	Max     int
	events  map[string]buffered
}

type buffered struct {
	at  time.Time
	raw json.RawMessage
}

// NewBuffer returns a buffer keeping events for horizon, up to max of them.
func NewBuffer(horizon time.Duration, max int) (*Buffer, error) {
	if horizon <= 0 || max <= 0 {
		return nil, errors.New("buffer horizon and size must be positive")
	}
	return &Buffer{Horizon: horizon, Max: max, events: map[string]buffered{}}, nil
}

// Add merges a Records envelope, as returned by Fetch, and reports how many
// events were new.
func (b *Buffer) Add(payload []byte) (int, error) {
	var doc struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return 0, fmt.Errorf("decode events: %w", err)
	}
	added := 0
	for _, raw := range doc.Records {
		var meta struct {
			EventID   string    `json:"eventID"`
			EventTime time.Time `json:"eventTime"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil || meta.EventID == "" || meta.EventTime.IsZero() {
			return added, errors.New("event is missing eventID or eventTime")
		}
		if _, seen := b.events[meta.EventID]; !seen {
			b.events[meta.EventID] = buffered{at: meta.EventTime, raw: raw}
			added++
		}
	}
	return added, nil
}

// Payload drops expired events and returns the rest as a Records envelope,
// ordered by time and then event ID, with the number of events.
func (b *Buffer) Payload(now time.Time) ([]byte, int, error) {
	type item struct {
		id string
		buffered
	}
	cutoff := now.Add(-b.Horizon)
	items := make([]item, 0, len(b.events))
	for id, ev := range b.events {
		if ev.at.Before(cutoff) {
			delete(b.events, id)
			continue
		}
		items = append(items, item{id, ev})
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].at.Equal(items[j].at) {
			return items[i].at.Before(items[j].at)
		}
		return items[i].id < items[j].id
	})
	if len(items) > b.Max {
		for _, old := range items[:len(items)-b.Max] {
			delete(b.events, old.id)
		}
		items = items[len(items)-b.Max:]
	}
	records := make([]json.RawMessage, len(items))
	for i, it := range items {
		records[i] = it.raw
	}
	payload, err := json.Marshal(struct {
		Records []json.RawMessage `json:"Records"`
	}{records})
	return payload, len(records), err
}
