package jsonrpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/Bidon15/popsigner/control-plane/internal/middleware"
	"github.com/Bidon15/popsigner/control-plane/internal/models"
	"github.com/Bidon15/popsigner/control-plane/internal/repository"
	"github.com/Bidon15/popsigner/control-plane/internal/service"
)

// API key scopes the JSON-RPC methods require.
const (
	scopeKeysRead = "keys:read"
	scopeKeysSign = "keys:sign"
)

// requireScope rejects the call when it was authenticated with an API key that
// lacks the scope. Session-authenticated calls carry no API key and are allowed.
func requireScope(ctx context.Context, scope string) *Error {
	apiKey := middleware.GetAPIKeyFromContext(ctx)
	if apiKey == nil || apiKey.HasScope(scope) {
		return nil
	}
	return ErrUnauthorized(fmt.Sprintf("API key does not have required scope: %s", scope))
}

// resolveKey looks up an organization key by Ethereum address and enforces the
// caller's key binding. A key the caller may not use is reported as unknown so
// the binding cannot be probed.
func resolveKey(ctx context.Context, keyRepo repository.KeyRepository, orgID uuid.UUID, ethAddress string) (*models.Key, *Error) {
	key, err := keyRepo.GetByEthAddress(ctx, orgID, ethAddress)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("failed to lookup key: %v", err))
	}
	if key == nil || !service.AllowsKey(ctx, key.ID) {
		return nil, ErrResourceNotFound(fmt.Sprintf("no key found for address %s", ethAddress))
	}
	return key, nil
}
