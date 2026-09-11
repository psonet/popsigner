package jsonrpc

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/Bidon15/popsigner/control-plane/internal/middleware"
	"github.com/Bidon15/popsigner/control-plane/internal/repository"
	"github.com/Bidon15/popsigner/control-plane/internal/service"
)

// EthAccountsHandler handles eth_accounts requests.
type EthAccountsHandler struct {
	keyRepo repository.KeyRepository
}

// NewEthAccountsHandler creates a new eth_accounts handler.
func NewEthAccountsHandler(keyRepo repository.KeyRepository) *EthAccountsHandler {
	return &EthAccountsHandler{keyRepo: keyRepo}
}

// Handle implements the eth_accounts JSON-RPC method.
// Returns a list of Ethereum addresses owned by the authenticated organization.
func (h *EthAccountsHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, *Error) {
	// Get org ID from context (set by auth middleware)
	orgID := middleware.GetOrgIDFromContext(ctx)
	if orgID.String() == "00000000-0000-0000-0000-000000000000" {
		return nil, ErrUnauthorized("missing organization context")
	}

	if scopeErr := requireScope(ctx, scopeKeysRead); scopeErr != nil {
		return nil, scopeErr
	}

	if identity, ok := service.APIKeyIdentityFromContext(ctx); ok && len(identity.AllowedKeyIDs) > 0 {
		return h.boundAddresses(ctx, orgID)
	}

	// List all Ethereum addresses for the org
	addresses, err := h.keyRepo.ListEthAddresses(ctx, orgID)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}

	// Return as array of strings (empty array if none)
	// OP Stack expects: ["0x...", "0x..."]
	if addresses == nil {
		addresses = []string{}
	}

	return addresses, nil
}

// boundAddresses returns the Ethereum addresses of the keys the caller is bound to.
func (h *EthAccountsHandler) boundAddresses(ctx context.Context, orgID uuid.UUID) (interface{}, *Error) {
	keys, err := h.keyRepo.ListByOrg(ctx, orgID)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}

	addresses := []string{}
	for _, key := range keys {
		if key.EthAddress != nil && *key.EthAddress != "" && service.AllowsKey(ctx, key.ID) {
			addresses = append(addresses, *key.EthAddress)
		}
	}
	return addresses, nil
}

