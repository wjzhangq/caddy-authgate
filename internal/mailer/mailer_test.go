package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	var got Request
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		hdr = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	m := New(srv.URL, map[string]string{"Authorization": "Bearer t", "X-Extra": "1"})
	status, err := m.Send(context.Background(), "alice@example.com", "012345", 5*time.Minute)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("Send = %d %v", status, err)
	}
	if got.Email != "alice@example.com" || got.Subject != Subject {
		t.Errorf("body = %+v", got)
	}
	if !strings.Contains(got.HTML, "<b>012345</b>") || !strings.Contains(got.HTML, "5 分钟内有效") {
		t.Errorf("html = %s", got.HTML)
	}
	if hdr.Get("Authorization") != "Bearer t" || hdr.Get("X-Extra") != "1" || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
		t.Errorf("headers = %v", hdr)
	}
}

func TestSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	status, err := New(srv.URL, nil).Send(context.Background(), "a@b.c", "000000", time.Minute)
	var ue *UpstreamError
	if status != 500 || !errors.As(err, &ue) || ue.Status != 500 || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Send = %d %v", status, err)
	}
}

func TestSendTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)
	m := New(srv.URL, nil)
	m.Client.Timeout = 50 * time.Millisecond
	status, err := m.Send(context.Background(), "a@b.c", "000000", time.Minute)
	if err == nil || status != 0 {
		t.Fatalf("Send = %d %v", status, err)
	}
}

func TestSendBadURL(t *testing.T) {
	m := &Mailer{URL: "://bad"}
	if _, err := m.Send(context.Background(), "a@b.c", "1", time.Minute); err == nil {
		t.Fatal("expected error")
	}
	m = &Mailer{URL: "http://127.0.0.1:1"}
	if _, err := m.Send(context.Background(), "a@b.c", "1", time.Minute); err == nil {
		t.Fatal("expected error")
	}
}

func TestMinutes(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, 30 * time.Second: 1, 5 * time.Minute: 5, 90 * time.Second: 2} {
		if got := Minutes(d); got != want {
			t.Errorf("Minutes(%v) = %d", d, got)
		}
	}
}
