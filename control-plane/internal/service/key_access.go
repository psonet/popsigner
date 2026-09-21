package service

import (
	"context"

	"github.com/google/uuid"
)

// apiKeyIdentityKey is the context key for the calling API key's identity.
// Unexported so only WithAPIKeyIdentity can populate it.
type apiKeyIdentityKey struct{}

// APIKeyIdentity describes the API key a request was authenticated with.
// An empty AllowedKeyIDs means the credential may use every key of its organization.
type APIKeyIdentity struct {
	KeyID         uuid.UUID
	AllowedKeyIDs []uuid.UUID
	IPAddress     string
	UserAgent     string
}

// WithAPIKeyIdentity returns a context carrying the API key identity.
func WithAPIKeyIdentity(ctx context.Context, identity APIKeyIdentity) context.Context {
	return context.WithValue(ctx, apiKeyIdentityKey{}, identity)
}

// APIKeyIdentityFromContext returns the API key identity stored in the context.
func APIKeyIdentityFromContext(ctx context.Context) (APIKeyIdentity, bool) {
	identity, ok := ctx.Value(apiKeyIdentityKey{}).(APIKeyIdentity)
	return identity, ok
}

// AllowsKey reports whether the calling credential may use the given key.
// Requests without an API key identity, and API keys without a binding, are unrestricted.
func AllowsKey(ctx context.Context, keyID uuid.UUID) bool {
	identity, ok := APIKeyIdentityFromContext(ctx)
	if !ok || len(identity.AllowedKeyIDs) == 0 {
		return true
	}
	for _, allowed := range identity.AllowedKeyIDs {
		if allowed == keyID {
			return true
		}
	}
	return false
}
