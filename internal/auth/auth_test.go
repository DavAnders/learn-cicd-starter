package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("No Authorization header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("Malformed Authorization header", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"MalformedApiKey"},
		}

		_, err := GetAPIKey(headers)
		if err == nil || !strings.Contains(err.Error(), "malformed authorization header") {
			t.Errorf("Expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("Valid Authorization header", func(t *testing.T) {
		expectedApiKey := "12345"
		headers := http.Header{
			"Authorization": []string{"ApiKey " + expectedApiKey},
		}

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if apiKey != expectedApiKey {
			t.Errorf("Expected %s, got %s", expectedApiKey, apiKey)
		}
	})
}
