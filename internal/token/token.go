// Package token 签发与校验 AuthGate 登录 token。
//
// 格式：v1.<b64url(payload)>.<b64url(HMAC-SHA256(secret, "v1."+b64url(payload)))>，
// payload 为 {"u":用户,"iat":签发时间,"exp":过期时间,"n":随机数}。
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const version = "v1"

// SecretLen 是自动生成的签名密钥长度。
const SecretLen = 32

// 错误定义。
var (
	ErrMalformed = errors.New("malformed token")
	ErrSignature = errors.New("invalid token signature")
	ErrExpired   = errors.New("token expired")
)

var b64 = base64.RawURLEncoding

type payload struct {
	U   string `json:"u"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	N   string `json:"n"`
}

// Signer 使用 HMAC-SHA256 签发与校验 token。
type Signer struct {
	secret []byte
	// Now 返回当前时间，测试时可替换。
	Now func() time.Time
}

// NewSigner 创建 Signer。
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: append([]byte(nil), secret...), Now: time.Now}
}

func (s *Signer) mac(msg string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// Sign 为 user 签发有效期为 ttl 的 token。
func (s *Signer) Sign(user string, ttl time.Duration) (string, time.Time) {
	now := s.Now()
	exp := now.Add(ttl).Truncate(time.Second)
	var n [8]byte
	if _, err := rand.Read(n[:]); err != nil {
		panic("token: crypto/rand failed: " + err.Error())
	}
	body, _ := json.Marshal(payload{U: user, Iat: now.Unix(), Exp: exp.Unix(), N: hex.EncodeToString(n[:])})
	signed := version + "." + b64.EncodeToString(body)
	return signed + "." + b64.EncodeToString(s.mac(signed)), exp
}

// Verify 校验 token 签名与有效期，返回用户名与过期时间。
func (s *Signer) Verify(tok string, now time.Time) (string, time.Time, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != version {
		return "", time.Time{}, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return "", time.Time{}, ErrMalformed
	}
	if !hmac.Equal(sig, s.mac(parts[0]+"."+parts[1])) {
		return "", time.Time{}, ErrSignature
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, ErrMalformed
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil || p.U == "" {
		return "", time.Time{}, ErrMalformed
	}
	exp := time.Unix(p.Exp, 0)
	if !now.Before(exp) {
		return "", time.Time{}, ErrExpired
	}
	return p.U, exp, nil
}

// LoadSecret 返回签名密钥：configured 非空时直接使用；
// 否则读取 <file>.secret，不存在时生成 32 字节随机密钥并以 0600 写入。
func LoadSecret(configured, file string) ([]byte, error) {
	if configured != "" {
		return []byte(configured), nil
	}
	path := file + ".secret"
	if b, err := os.ReadFile(path); err == nil {
		if len(b) < SecretLen {
			return nil, fmt.Errorf("secret file %s is too short (%d bytes)", path, len(b))
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, SecretLen)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadSecret("", file)
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(secret); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return secret, f.Close()
}
