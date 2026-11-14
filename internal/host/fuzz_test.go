package host

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzLoadAndScan(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	for _, p := range paths {
		if raw, err := os.ReadFile(p); err == nil {
			f.Add(raw)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := Load(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, finding := range Scan(snap) {
			if finding.Confidence < 0 || finding.Confidence >= 100 {
				t.Fatalf("confidence out of range: %v", finding.Confidence)
			}
		}
	})
}

// FuzzRedactCmdline checks that a value following a secret flag never survives.
func FuzzRedactCmdline(f *testing.F) {
	f.Add("--password", "v1")
	f.Add("--api-key", "v2")
	f.Add("-p", "v3")
	f.Fuzz(func(t *testing.T, flag, value string) {
		// Skip values that are not one argument, or that occur in the fixed
		// text around them (the "a" in "app", for example).
		if value == "" || strings.ContainsAny(value, "* \t\n") || strings.Contains("app --password=*** --token ***", value) {
			return
		}
		out := RedactCmdline([]string{"app", "--password=" + value, "--token", value})
		if strings.Contains(strings.Join(out, " "), value) {
			t.Fatalf("secret %q survived: %v", value, out)
		}
		RedactCmdline([]string{flag, value}) // must not panic
		parseAddr(flag + ":" + value)
		parseStat([]byte(flag + ")" + value))
	})
}
