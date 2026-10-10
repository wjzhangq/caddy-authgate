package token

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

var t0 = time.Unix(1760000000, 0)

func newSigner(secret string) *Signer {
	s := NewSigner([]byte(secret))
	s.Now = func() time.Time { return t0 }
	return s
}

func TestSignVerify(t *testing.T) {
	s := newSigner(strings.Repeat("x", 32))
	tok, exp := s.Sign("alice", time.Hour)
	if !exp.Equal(t0.Add(time.Hour)) {
		t.Errorf("exp = %v", exp)
	}
	if !strings.HasPrefix(tok, "v1.") || strings.Count(tok, ".") != 2 {
		t.Fatalf("tok = %s", tok)
	}
	u, e, err := s.Verify(tok, t0.Add(time.Minute))
	if err != nil || u != "alice" || !e.Equal(exp) {
		t.Fatalf("Verify = %q %v %v", u, e, err)
	}
	tok2, _ := s.Sign("alice", time.Hour)
	if tok2 == tok {
		t.Errorf("nonce should differ")
	}
}

func TestVerifyErrors(t *testing.T) {
	s := newSigner(strings.Repeat("x", 32))
	tok, _ := s.Sign("alice", time.Hour)
	parts := strings.Split(tok, ".")

	if _, _, err := s.Verify(tok, t0.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, _, err := newSigner(strings.Repeat("y", 32)).Verify(tok, t0); !errors.Is(err, ErrSignature) {
		t.Errorf("other secret: %v", err)
	}
	// 篡改用户名
	var p payload
	body, _ := b64.DecodeString(parts[1])
	_ = json.Unmarshal(body, &p)
	p.U = "admin"
	nb, _ := json.Marshal(p)
	forged := parts[0] + "." + b64.EncodeToString(nb) + "." + parts[2]
	if _, _, err := s.Verify(forged, t0); !errors.Is(err, ErrSignature) {
		t.Errorf("payload tamper: %v", err)
	}
	// 篡改签名
	sig := []byte(parts[2])
	sig[0] ^= 1
	if _, _, err := s.Verify(parts[0]+"."+parts[1]+"."+string(sig), t0); err == nil {
		t.Errorf("sig tamper accepted")
	}
	// 错误版本
	if _, _, err := s.Verify("v2."+parts[1]+"."+parts[2], t0); !errors.Is(err, ErrMalformed) {
		t.Errorf("version: %v", err)
	}
	for _, bad := range []string{"", "v1", "v1.a", "v1.a.b.c", "v1.a.!!"} {
		if _, _, err := s.Verify(bad, t0); !errors.Is(err, ErrMalformed) {
			t.Errorf("Verify(%q) = %v", bad, err)
		}
	}
	// 签名正确但 payload 非法
	for _, body := range []string{"!!", b64.EncodeToString([]byte("{")), b64.EncodeToString([]byte(`{"u":""}`))} {
		signed := "v1." + body
		tok := signed + "." + b64.EncodeToString(s.mac(signed))
		if _, _, err := s.Verify(tok, t0); !errors.Is(err, ErrMalformed) {
			t.Errorf("payload %q: %v", body, err)
		}
	}
}

func TestLoadSecret(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "users.txt")
	if b, err := LoadSecret("configured-secret", file); err != nil || string(b) != "configured-secret" {
		t.Fatalf("configured: %q %v", b, err)
	}
	a, err := LoadSecret("", file)
	if err != nil || len(a) != SecretLen {
		t.Fatalf("generate: %v %d", err, len(a))
	}
	fi, err := os.Stat(file + ".secret")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v %v", err, fi)
	}
	b, err := LoadSecret("", file)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("reuse: %v", err)
	}
	_ = os.WriteFile(file+".secret", []byte("short"), 0o600)
	if _, err := LoadSecret("", file); err == nil {
		t.Errorf("short secret accepted")
	}
	if _, err := LoadSecret("", filepath.Join(dir, "missing", "users.txt")); err == nil {
		t.Errorf("unwritable dir accepted")
	}
}
