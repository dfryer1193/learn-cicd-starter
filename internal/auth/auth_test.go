package auth

import (
	"errors"
	"net/http"
	"testing"
)

func Test_GetAPIKey(t *testing.T) {
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key_123"},
			},
			expectedKey:   "valid_api_key_123",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range testCases {
		key, err := GetAPIKey(tc.headers)
		if key != tc.expectedKey {
			t.Fatalf("Test %s failed: expected key %s, got %s", tc.name, tc.expectedKey, key)
		}

		if err != nil && tc.expectedError != nil {
			if err.Error() != tc.expectedError.Error() {
				t.Fatalf("Test %s failed: expected error %v, got %v", tc.name, tc.expectedError, err)
			}
		} else if err != tc.expectedError {
			t.Fatalf("Test %s failed: expected error %v, got %v", tc.name, tc.expectedError, err)
		}
	}
}
