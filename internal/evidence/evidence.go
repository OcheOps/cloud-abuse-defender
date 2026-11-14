// Package evidence keeps a tamper-evident, append-only log of incident
// records as JSON lines.
//
// Every record carries the SHA-256 hash of the previous record, and its own
// hash covers its content and that link. Editing, deleting, inserting or
// reordering any record breaks the chain from that point, which Verify
// reports. The chain is tamper-evident, not tamper-proof: someone who can
// write the file can rebuild the whole chain, so the head hash should also
// be kept somewhere else (alerts carry the hash of the record behind them).
//
// The log is local and may contain principal ARNs, source IPs and event IDs
// needed for investigation; it is written with owner-only permissions.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// ErrInvalid is wrapped by malformed or broken logs.
var ErrInvalid = errors.New("invalid evidence log")

// maxLine bounds one record so a corrupt file cannot exhaust memory.
const maxLine = 4 << 20

// Record is one entry in the log.
type Record struct {
	Seq        int64           `json:"seq"`
	Time       time.Time       `json:"time"`
	Kind       string          `json:"kind"`
	IncidentID string          `json:"incident_id"`
	Data       json.RawMessage `json:"data"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

// computeHash hashes the record's JSON encoding with Hash left empty.
func computeHash(r Record) (string, error) {
	r.Hash = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Head is the state at the end of a verified log.
type Head struct {
	Records int64  `json:"records"`
	Hash    string `json:"head_hash"`
}

// Verify checks every record's sequence, link and hash.
func Verify(r io.Reader) (Head, error) { return verify(r, nil) }

// verify calls each (if non-nil) with every record that passes its checks.
func verify(r io.Reader, each func(Record)) (Head, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	var head Head
	for line := 1; sc.Scan(); line++ {
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return head, fmt.Errorf("%w: line %d: %v", ErrInvalid, line, err)
		}
		switch {
		case rec.Seq != head.Records+1:
			return head, fmt.Errorf("%w: line %d: sequence %d, want %d (record missing, inserted or reordered)", ErrInvalid, line, rec.Seq, head.Records+1)
		case rec.PrevHash != head.Hash:
			return head, fmt.Errorf("%w: line %d (seq %d): previous-hash link broken", ErrInvalid, line, rec.Seq)
		}
		want, err := computeHash(rec)
		if err != nil {
			return head, fmt.Errorf("%w: line %d: %v", ErrInvalid, line, err)
		}
		if rec.Hash != want {
			return head, fmt.Errorf("%w: line %d (seq %d): hash mismatch (record modified)", ErrInvalid, line, rec.Seq)
		}
		// The hash covers the decoded values, and JSON decoding is lenient
		// (key case, whitespace, duplicate keys). Requiring the exact bytes
		// Append wrote closes that gap: any edit at all is detected.
		canonical, err := json.Marshal(rec)
		if err != nil || !bytes.Equal(canonical, sc.Bytes()) {
			return head, fmt.Errorf("%w: line %d (seq %d): record is not in the form it was written (modified)", ErrInvalid, line, rec.Seq)
		}
		head = Head{Records: rec.Seq, Hash: rec.Hash}
		if each != nil {
			each(rec)
		}
	}
	if err := sc.Err(); err != nil {
		return head, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return head, nil
}

// Log appends records to a verified log file. It assumes a single writer.
type Log struct {
	f    *os.File
	head Head
}

// Open verifies an existing log (or creates an empty one) and opens it for
// appending. A log that fails verification is never appended to.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	head, err := Verify(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Log{f: f, head: head}, nil
}

// Head returns the current end of the chain.
func (l *Log) Head() Head { return l.head }

// Append writes one record and returns it with its hash.
func (l *Log) Append(kind, incidentID string, data any, now time.Time) (Record, error) {
	if kind == "" {
		return Record{}, fmt.Errorf("%w: record kind is required", ErrInvalid)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	rec := Record{
		Seq:        l.head.Records + 1,
		Time:       now.UTC(),
		Kind:       kind,
		IncidentID: incidentID,
		Data:       raw,
		PrevHash:   l.head.Hash,
	}
	if rec.Hash, err = computeHash(rec); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	l.head = Head{Records: rec.Seq, Hash: rec.Hash}
	return rec, nil
}

// Close closes the log file.
func (l *Log) Close() error { return l.f.Close() }

// VerifyFile verifies the log at path. A missing file is an error.
func VerifyFile(path string) (Head, error) { return verifyFile(path, nil) }

// VerifyFileContains verifies the log and reports whether a record with the
// given hash is part of the valid chain. A hash kept outside the log (for
// example from an alert) that is missing means the log was truncated past
// that record or rebuilt.
func VerifyFileContains(path, hash string) (Head, bool, error) {
	found := false
	head, err := verifyFile(path, func(r Record) {
		if r.Hash == hash {
			found = true
		}
	})
	return head, found, err
}

// ReadFile verifies the log and returns all of its records in order.
func ReadFile(path string) ([]Record, Head, error) {
	var recs []Record
	head, err := verifyFile(path, func(r Record) { recs = append(recs, r) })
	if err != nil {
		return nil, head, err
	}
	return recs, head, nil
}

func verifyFile(path string, each func(Record)) (Head, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Head{}, fmt.Errorf("%w: %s does not exist", ErrInvalid, path)
	}
	if err != nil {
		return Head{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	defer f.Close()
	head, err := verify(f, each)
	if err != nil {
		return head, fmt.Errorf("%s: %w", path, err)
	}
	return head, nil
}
