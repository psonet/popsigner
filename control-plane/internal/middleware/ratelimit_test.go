package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRateLimitBuckets(t *testing.T) {
	const credential = "bbr_live_abcdefgh0123456789"

	tests := []struct {
		name       string
		headers    map[string]string
		wantApiKey bool
	}{
		{
			name:    "no credential",
			headers: map[string]string{},
		},
		{
			name:       "bearer credential",
			headers:    map[string]string{"Authorization": "Bearer " + credential},
			wantApiKey: true,
		},
		{
			name:       "apikey credential",
			headers:    map[string]string{"Authorization": "ApiKey " + credential},
			wantApiKey: true,
		},
		{
			name:       "x-api-key credential",
			headers:    map[string]string{"X-API-Key": credential},
			wantApiKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/keys", nil)
			r.RemoteAddr = "192.0.2.10:4711"
			for name, value := range tt.headers {
				r.Header.Set(name, value)
			}

			buckets := rateLimitBuckets(r)

			var sawIP, sawAPIKey bool
			for _, bucket := range buckets {
				if strings.Contains(bucket, credential) {
					t.Errorf("bucket %q contains the raw credential", bucket)
				}
				switch {
				case strings.HasPrefix(bucket, "ip:"):
					sawIP = true
				case strings.HasPrefix(bucket, "apikey:"):
					sawAPIKey = true
					if len(bucket) != len("apikey:")+32 {
						t.Errorf("bucket %q is not a 16-byte hex digest", bucket)
					}
				default:
					t.Errorf("unexpected bucket %q", bucket)
				}
			}

			if !sawIP {
				t.Error("the IP bucket is missing")
			}
			if sawAPIKey != tt.wantApiKey {
				t.Errorf("API key bucket present = %v, want %v", sawAPIKey, tt.wantApiKey)
			}
		})
	}

	t.Run("the same credential always lands in the same bucket", func(t *testing.T) {
		bucketFor := func(remoteAddr string) string {
			r := httptest.NewRequest("POST", "/v1/keys", nil)
			r.RemoteAddr = remoteAddr
			r.Header.Set("Authorization", "Bearer "+credential)
			return rateLimitBuckets(r)[0]
		}

		if first, second := bucketFor("192.0.2.10:4711"), bucketFor("198.51.100.4:1234"); first != second {
			t.Errorf("bucket = %q and %q for the same credential", first, second)
		}
	})
}

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name:       "remote address",
			remoteAddr: "192.0.2.10:4711",
			want:       "192.0.2.10:4711",
		},
		{
			name:       "real ip header",
			headers:    map[string]string{"X-Real-IP": "198.51.100.4"},
			remoteAddr: "192.0.2.10:4711",
			want:       "198.51.100.4",
		},
		{
			name:       "single forwarded hop",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.4"},
			remoteAddr: "192.0.2.10:4711",
			want:       "198.51.100.4",
		},
		{
			name:       "multiple forwarded hops use the client",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.4, 203.0.113.7, 192.0.2.1"},
			remoteAddr: "192.0.2.10:4711",
			want:       "198.51.100.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/keys", nil)
			r.RemoteAddr = tt.remoteAddr
			for name, value := range tt.headers {
				r.Header.Set(name, value)
			}

			if got := getRealIP(r); got != tt.want {
				t.Errorf("getRealIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
