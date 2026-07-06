package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers         http.Header
		wantKey         string
		wantErrSentinel error
		wantAnyErr      bool
	}{
		"no authorization header": {
			headers:         http.Header{},
			wantKey:         "",
			wantErrSentinel: ErrNoAuthHeaderIncluded,
		},
		"valid ApiKey header": {
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		"wrong scheme": {
			headers:    http.Header{"Authorization": []string{"Bearer my-token"}},
			wantKey:    "",
			wantAnyErr: true,
		},
		"missing key value": {
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantAnyErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)
			if gotKey != tc.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tc.wantKey)
			}
			if tc.wantErrSentinel != nil && gotErr != tc.wantErrSentinel {
				t.Errorf("error: got %v, want %v", gotErr, tc.wantErrSentinel)
			}
			if tc.wantAnyErr && gotErr == nil {
				t.Errorf("expected an error but got nil")
			}
			if tc.wantErrSentinel == nil && !tc.wantAnyErr && gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			}
		})
	}
}
