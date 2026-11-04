package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 123456789, time.FixedZone("x", 3600))

func writeLog(t *testing.T, n int) (string, []Record) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var recs []Record
	for i := 0; i < n; i++ {
		r, err := l.Append("finding", "inc_1", map[string]any{"n": i, "note": "<&>"}, t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return path, recs
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func rewrite(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppendAndVerify(t *testing.T) {
	path, recs := writeLog(t, 3)
	if recs[0].Seq != 1 || recs[0].PrevHash != "" || recs[1].PrevHash != recs[0].Hash || recs[2].Seq != 3 {
		t.Fatalf("chain not linked: %+v", recs)
	}
	if recs[0].Time.Location() != time.UTC {
		t.Fatal("record time must be UTC")
	}
	head, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if head.Records != 3 || head.Hash != recs[2].Hash {
		t.Fatalf("unexpected head: %+v", head)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path, recs := writeLog(t, 2)
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.Head().Hash != recs[1].Hash {
		t.Fatalf("head not restored: %+v", l.Head())
	}
	r, err := l.Append("notification", "inc_1", map[string]string{"status": "sent"}, t0)
	l.Close()
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 3 || r.PrevHash != recs[1].Hash {
		t.Fatalf("append after reopen not linked: %+v", r)
	}
	if head, err := VerifyFile(path); err != nil || head.Records != 3 {
		t.Fatalf("verify after reopen: %+v %v", head, err)
	}
}

func TestEmptyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	head, err := VerifyFile(path)
	if err != nil || head.Records != 0 || head.Hash != "" {
		t.Fatalf("empty log: %+v %v", head, err)
	}
}

func TestTamperingDetected(t *testing.T) {
	tests := map[string]func([]string) []string{
		"edited data": func(ls []string) []string {
			ls[1] = strings.Replace(ls[1], `"n":1`, `"n":9`, 1)
			return ls
		},
		"edited time": func(ls []string) []string {
			// Stored in UTC: t0 (10:00 at UTC+1) is written as 09:00.
			if !strings.Contains(ls[0], "T09:00:00") {
				panic("fixture time not found: " + ls[0])
			}
			ls[0] = strings.Replace(ls[0], "T09:00:00", "T09:59:00", 1)
			return ls
		},
		"deleted record": func(ls []string) []string { return append(ls[:1], ls[2:]...) },
		"deleted last":   func(ls []string) []string { return ls }, // control: truncating the tail is undetectable locally
		"reordered":      func(ls []string) []string { ls[0], ls[1] = ls[1], ls[0]; return ls },
		"duplicated":     func(ls []string) []string { return append(ls[:2], ls[1:]...) },
		"recomputed hash without relinking": func(ls []string) []string {
			var r Record
			json.Unmarshal([]byte(ls[1]), &r)
			r.Data = json.RawMessage(`{"n":42}`)
			r.Hash, _ = computeHash(r)
			b, _ := json.Marshal(r)
			ls[1] = string(b)
			return ls
		},
		"not json":      func(ls []string) []string { ls[2] = "garbage"; return ls },
		"unknown field": func(ls []string) []string { ls[2] = strings.Replace(ls[2], `{"seq"`, `{"extra":1,"seq"`, 1); return ls },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			path, _ := writeLog(t, 3)
			ls := mutate(lines(t, path))
			if name == "deleted last" {
				ls = ls[:2]
			}
			rewrite(t, path, ls)
			_, err := VerifyFile(path)
			if name == "deleted last" {
				// Documented limit: dropping the newest records leaves a valid
				// shorter chain; the externally kept head hash catches it.
				if err != nil {
					t.Fatalf("truncated chain should still verify locally: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampering not detected: %v", err)
			}
		})
	}
}

func TestOpenRefusesBrokenLog(t *testing.T) {
	path, _ := writeLog(t, 2)
	ls := lines(t, path)
	ls[0] = strings.Replace(ls[0], `"n":0`, `"n":5`, 1)
	rewrite(t, path, ls)
	if _, err := Open(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open must refuse a broken log, got %v", err)
	}
	if got := lines(t, path); len(got) != 2 {
		t.Fatalf("broken log was modified: %d lines", len(got))
	}
}

func TestErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := VerifyFile(filepath.Join(dir, "missing.jsonl")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := Open(filepath.Join(dir, "no", "such", "dir.jsonl")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad path: %v", err)
	}
	if _, err := VerifyFile(dir); !errors.Is(err, ErrInvalid) {
		t.Fatalf("directory: %v", err)
	}
	l, err := Open(filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append("", "x", nil, t0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty kind: %v", err)
	}
	if _, err := l.Append("k", "x", func() {}, t0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unencodable data: %v", err)
	}
	if _, err := Verify(bytes.NewReader(bytes.Repeat([]byte("x"), maxLine+1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized line: %v", err)
	}
}

func TestVerifyFileContains(t *testing.T) {
	path, recs := writeLog(t, 3)
	if _, found, err := VerifyFileContains(path, recs[1].Hash); err != nil || !found {
		t.Fatalf("record not found: %v %v", found, err)
	}
	// Truncating past a record whose hash was kept elsewhere is caught.
	rewrite(t, path, lines(t, path)[:1])
	if _, found, err := VerifyFileContains(path, recs[1].Hash); err != nil || found {
		t.Fatalf("truncated record must be reported missing: %v %v", found, err)
	}
}

func TestReadFile(t *testing.T) {
	path, recs := writeLog(t, 3)
	got, head, err := ReadFile(path)
	if err != nil || len(got) != 3 || head.Hash != recs[2].Hash || got[1].Hash != recs[1].Hash {
		t.Fatalf("ReadFile: %d records, head %+v, %v", len(got), head, err)
	}
	ls := lines(t, path)
	ls[0] = strings.Replace(ls[0], `"n":0`, `"n":7`, 1)
	rewrite(t, path, ls)
	if got, _, err := ReadFile(path); !errors.Is(err, ErrInvalid) || got != nil {
		t.Fatalf("broken log must return no records: %v %v", got, err)
	}
}
