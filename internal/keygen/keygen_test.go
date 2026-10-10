package keygen

import (
	"testing"
	"time"
)

func TestNewFormat(t *testing.T) {
	now := time.Unix(1760000000, 0)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k := New(now)
		if len(k) != Len || len(k) != 27 {
			t.Fatalf("bad length %d: %s", len(k), k)
		}
		if !IsStandard(k) {
			t.Fatalf("not standard: %s", k)
		}
		if seen[k] {
			t.Fatalf("duplicate key %s", k)
		}
		seen[k] = true
		ts, ok := CreatedAt(k)
		if !ok || !ts.Equal(now) {
			t.Fatalf("CreatedAt = %v %v, want %v", ts, ok, now)
		}
	}
}

func TestCreatedAtNonStandard(t *testing.T) {
	for _, k := range []string{"", "abc", "sk-XYZ", "sk-0000000g0000000000000000", "sk-00000000000000000000000000", "pk-6900000000000000000000aa"} {
		if _, ok := CreatedAt(k); ok {
			t.Errorf("CreatedAt(%q) should fail", k)
		}
	}
}

func TestMask(t *testing.T) {
	if got := Mask("sk-68e8c80012345678abcdef01"); got != "sk-68e8…ef01" {
		t.Errorf("Mask = %q", got)
	}
	if got := Mask("short"); got != "…" {
		t.Errorf("Mask short = %q", got)
	}
}
