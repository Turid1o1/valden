package main

import (
	"regexp"
	"testing"
	"time"
)

func TestAllowedTransitions(t *testing.T) {
	cases := []struct {
		from string
		to   string
		ok   bool
	}{
		{from: statusRequested, to: statusNotified, ok: true},
		{from: statusNotified, to: statusAccepted, ok: true},
		{from: statusAccepted, to: statusConnecting, ok: true},
		{from: statusConnecting, to: statusConnected, ok: true},
		{from: statusConnected, to: statusReconnecting, ok: true},
		{from: statusReconnecting, to: statusConnected, ok: true},
		{from: statusRequested, to: statusConnected, ok: false},
		{from: statusEnded, to: statusConnecting, ok: false},
		{from: statusFailed, to: statusConnected, ok: false},
	}

	for _, tc := range cases {
		_, allowed := allowedTransitions[tc.from][tc.to]
		if allowed != tc.ok {
			t.Fatalf("transition %s -> %s expected allowed=%v got=%v", tc.from, tc.to, tc.ok, allowed)
		}
	}
}

func TestRateLimiterWindow(t *testing.T) {
	limiter := NewRateLimiter()
	key := "otp:test"
	window := 30 * time.Millisecond

	if !limiter.Allow(key, 2, window) {
		t.Fatal("first request must pass")
	}
	if !limiter.Allow(key, 2, window) {
		t.Fatal("second request must pass")
	}
	if limiter.Allow(key, 2, window) {
		t.Fatal("third request must be blocked")
	}

	time.Sleep(40 * time.Millisecond)

	if !limiter.Allow(key, 2, window) {
		t.Fatal("request after window expiry must pass")
	}
}

func TestRandomOTPFormat(t *testing.T) {
	re := regexp.MustCompile(`^\d{6}$`)

	for i := 0; i < 20; i++ {
		otp, err := randomOTP()
		if err != nil {
			t.Fatalf("randomOTP error: %v", err)
		}
		if !re.MatchString(otp) {
			t.Fatalf("otp has invalid format: %q", otp)
		}
	}
}

func TestConstantTimeEquals(t *testing.T) {
	if !constantTimeEquals("abc", "abc") {
		t.Fatal("equal strings must return true")
	}
	if constantTimeEquals("abc", "abcd") {
		t.Fatal("different length strings must return false")
	}
	if constantTimeEquals("abc", "abx") {
		t.Fatal("different strings must return false")
	}
}
