package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAllowsKey(t *testing.T) {
	bound := uuid.New()
	other := uuid.New()

	tests := []struct {
		name     string
		identity *APIKeyIdentity
		keyID    uuid.UUID
		want     bool
	}{
		{
			name:  "no identity is unrestricted",
			keyID: bound,
			want:  true,
		},
		{
			name:     "nil binding is unrestricted",
			identity: &APIKeyIdentity{KeyID: uuid.New()},
			keyID:    bound,
			want:     true,
		},
		{
			name:     "empty binding is unrestricted",
			identity: &APIKeyIdentity{KeyID: uuid.New(), AllowedKeyIDs: []uuid.UUID{}},
			keyID:    bound,
			want:     true,
		},
		{
			name:     "bound key is allowed",
			identity: &APIKeyIdentity{KeyID: uuid.New(), AllowedKeyIDs: []uuid.UUID{bound}},
			keyID:    bound,
			want:     true,
		},
		{
			name:     "unbound key is refused",
			identity: &APIKeyIdentity{KeyID: uuid.New(), AllowedKeyIDs: []uuid.UUID{bound}},
			keyID:    other,
			want:     false,
		},
		{
			name:     "any of several bound keys is allowed",
			identity: &APIKeyIdentity{KeyID: uuid.New(), AllowedKeyIDs: []uuid.UUID{other, bound}},
			keyID:    bound,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.identity != nil {
				ctx = WithAPIKeyIdentity(ctx, *tt.identity)
			}
			if got := AllowsKey(ctx, tt.keyID); got != tt.want {
				t.Errorf("AllowsKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIKeyIdentityFromContext(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		if _, ok := APIKeyIdentityFromContext(context.Background()); ok {
			t.Error("APIKeyIdentityFromContext() found an identity in a bare context")
		}
	})

	t.Run("round trips", func(t *testing.T) {
		want := APIKeyIdentity{
			KeyID:         uuid.New(),
			AllowedKeyIDs: []uuid.UUID{uuid.New()},
			IPAddress:     "203.0.113.7",
			UserAgent:     "popsigner-sdk/1.0",
		}

		got, ok := APIKeyIdentityFromContext(WithAPIKeyIdentity(context.Background(), want))
		if !ok {
			t.Fatal("APIKeyIdentityFromContext() did not find the identity")
		}
		if got.KeyID != want.KeyID || got.IPAddress != want.IPAddress || got.UserAgent != want.UserAgent {
			t.Errorf("identity = %+v, want %+v", got, want)
		}
		if len(got.AllowedKeyIDs) != 1 || got.AllowedKeyIDs[0] != want.AllowedKeyIDs[0] {
			t.Errorf("AllowedKeyIDs = %v, want %v", got.AllowedKeyIDs, want.AllowedKeyIDs)
		}
	})
}
