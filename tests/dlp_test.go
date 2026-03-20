package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axcerberus/internal/dlp"
)

func TestDLPLuhnValid(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},  // Visa test
		{"5500000000000004", true},  // MC test
		{"340000000000009", true},   // Amex test
		{"1234567890123456", false}, // Invalid
		{"0000000000000000", true},  // All zeros passes Luhn
	}
	for _, tc := range tests {
		if got := dlp.LuhnValid(tc.number); got != tc.valid {
			t.Errorf("LuhnValid(%s) = %v, want %v", tc.number, got, tc.valid)
		}
	}
}

func TestDLPCreditCardDetection(t *testing.T) {
	scanner := dlp.NewScanner("log", true, false, false)

	// Visa test card (passes Luhn)
	body := []byte(`{"card": "4111111111111111"}`)
	matches := scanner.Scan(body)
	if len(matches) == 0 {
		t.Fatal("expected credit card match")
	}
	if matches[0].Type != dlp.PatternCreditCard {
		t.Fatalf("expected credit_card type, got %s", matches[0].Type)
	}
}

func TestDLPCreditCardLuhnRejects(t *testing.T) {
	scanner := dlp.NewScanner("log", true, false, false)

	// Invalid card number (fails Luhn)
	body := []byte(`{"card": "4111111111111112"}`)
	matches := scanner.Scan(body)
	if len(matches) != 0 {
		t.Fatal("invalid CC number should not match (fails Luhn)")
	}
}

func TestDLPAPIKeyDetection(t *testing.T) {
	scanner := dlp.NewScanner("log", false, true, false)

	tests := []struct {
		name string
		body string
	}{
		{"AWS", `{"key": "AKIAIOSFONN7EXAMPLE"}`},
		{"GitHub", `{"token": "ghp_aBcDeFgHiJkLmNoPsTuVwXyZ0123456789"}`},
		{"Stripe", `{"key": "sk_test_FaKeKeyForDLPUnitTest0000"}`},
	}

	for _, tc := range tests {
		matches := scanner.Scan([]byte(tc.body))
		if len(matches) == 0 {
			t.Fatalf("%s: expected API key match", tc.name)
		}
		if matches[0].Type != dlp.PatternAPIKey {
			t.Fatalf("%s: expected api_key type, got %s", tc.name, matches[0].Type)
		}
	}
}

func TestDLPStackTraceDetection(t *testing.T) {
	scanner := dlp.NewScanner("log", false, false, true)

	tests := []struct {
		name string
		body string
	}{
		{"Python", `Traceback (most recent call last)`},
		{"Go", `panic: runtime error: invalid memory address`},
		{"MySQL", `You have an error in your SQL syntax`},
		{"PostgreSQL", `ERROR: relation "users" does not exist`},
	}

	for _, tc := range tests {
		matches := scanner.Scan([]byte(tc.body))
		if len(matches) == 0 {
			t.Fatalf("%s: expected stack trace or db error match", tc.name)
		}
	}
}

func TestDLPInternalIPDetection(t *testing.T) {
	scanner := dlp.NewScanner("log", false, false, false) // internal IP is always checked

	body := []byte(`{"server": "10.0.1.5", "db": "192.168.1.100"}`)
	matches := scanner.Scan(body)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 internal IP matches, got %d", len(matches))
	}
}

func TestDLPBlockMode(t *testing.T) {
	scanner := dlp.NewScanner("block", true, false, false)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`Card: 4111111111111111`))
	})
	mw := scanner.Middleware(upstream)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("block mode should return 500, got %d", rec.Code)
	}
}

func TestDLPMaskMode(t *testing.T) {
	scanner := dlp.NewScanner("mask", true, false, false)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`Card: 4111111111111111`))
	})
	mw := scanner.Middleware(upstream)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "4111111111111111") {
		t.Fatal("mask mode should redact CC number")
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatal("mask mode should replace with [REDACTED]")
	}
}

func TestDLPLogMode(t *testing.T) {
	detected := false
	scanner := dlp.NewScanner("log", true, false, false)
	scanner.OnDetect = func(event dlp.Event) {
		detected = true
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`Card: 4111111111111111`))
	})
	mw := scanner.Middleware(upstream)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	// Log mode should pass response through unchanged
	if rec.Code != http.StatusOK {
		t.Fatalf("log mode should return 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "4111111111111111") {
		t.Fatal("log mode should not modify response")
	}
	if !detected {
		t.Fatal("OnDetect callback should have been called")
	}
}

func TestDLPBinarySkip(t *testing.T) {
	scanner := dlp.NewScanner("block", true, true, true)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`4111111111111111`)) // Would match as CC
	})
	mw := scanner.Middleware(upstream)

	req := httptest.NewRequest("GET", "/image.png", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("binary content should skip DLP, got %d", rec.Code)
	}
}

func TestDLPNoMatch(t *testing.T) {
	scanner := dlp.NewScanner("block", true, true, true)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Hello, World!</body></html>`))
	})
	mw := scanner.Middleware(upstream)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("clean content should pass, got %d", rec.Code)
	}
}
