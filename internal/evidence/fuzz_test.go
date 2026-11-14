package evidence

import (
	"bytes"
	"os"
	"testing"
)

// FuzzVerify checks that Verify never panics and never accepts a log whose
// chain it did not fully check.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte(`{"seq":1,"time":"2026-11-04T10:00:00Z","kind":"finding","incident_id":"i","data":{},"prev_hash":"","hash":"x"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		head, err := Verify(bytes.NewReader(data))
		if err == nil && head.Records > 0 && head.Hash == "" {
			t.Fatal("verified log with records but no head hash")
		}
	})
}

// FuzzSingleByteTamper checks that changing any single byte of a valid log
// is detected. It found that changing a key's case ("seq" to "Seq") went
// unnoticed before Verify compared each line with its canonical form.
func FuzzSingleByteTamper(f *testing.F) {
	f.Add(uint16(10), byte('x'))
	f.Add(uint16(200), byte('0'))
	f.Fuzz(func(t *testing.T, pos uint16, b byte) {
		path, recs := writeLog(t, 3)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		i := int(pos) % len(raw)
		if raw[i] == b {
			return
		}
		raw[i] = b
		head, err := Verify(bytes.NewReader(raw))
		if err == nil && head.Records == 3 && head.Hash == recs[2].Hash {
			t.Fatalf("modified log verified with the original head (byte %d -> %q)", i, b)
		}
	})
}
