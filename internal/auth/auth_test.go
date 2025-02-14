package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		expected  string
		expectErr error
	}{
		{
			name:      "Valid API Key",
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expected:  "my-secret-key",
			expectErr: nil,
		},
		{
			name:      "Missing Authorization Header",
			headers:   http.Header{},
			expected:  "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "Malformed Authorization Header - No ApiKey Prefix",
			headers:   http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "Malformed Authorization Header - Missing Key",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expected {
				t.Errorf("expected key %q, got %q", tt.expected, key)
			}

			if (err != nil && tt.expectErr == nil) || (err == nil && tt.expectErr != nil) || (err != nil && tt.expectErr != nil && err.Error() != tt.expectErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}
		})
	}
}
