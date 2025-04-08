package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyBlankHeader(t *testing.T) {
	header := http.Header{}
	_, err := GetAPIKey(header)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("Should be ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	malformedHeader := http.Header{}
	malformedHeader.Add("Authorization", "ApiKey")

	_, err := GetAPIKey(malformedHeader)
	if err == nil {
		t.Fatalf("Expected malformed authorization header")
	}
}

func TestGetAPIKeyGood(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "ApiKey supersecurekey")

	key, err := GetAPIKey(header)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if key != "supersecurekey" {
		t.Fatalf("Expected value 'supersecurekey', got %v", key)
	}
}
