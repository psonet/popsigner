package jsonrpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/Bidon15/popsigner/control-plane/internal/middleware"
	"github.com/Bidon15/popsigner/control-plane/internal/models"
	"github.com/Bidon15/popsigner/control-plane/internal/service"
)

func contextWithAPIKey(orgID uuid.UUID, apiKey *models.APIKey) context.Context {
	ctx := context.WithValue(contextWithOrgID(orgID), middleware.APIKeyContextKey, apiKey)
	return service.WithAPIKeyIdentity(ctx, service.APIKeyIdentity{
		KeyID:         apiKey.ID,
		AllowedKeyIDs: apiKey.AllowedKeyIDs,
	})
}

func TestRequireScope(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    *models.APIKey
		wantError bool
	}{
		{name: "session auth has no API key", apiKey: nil},
		{name: "scope present", apiKey: &models.APIKey{ID: uuid.New(), Scopes: []string{"keys:sign"}}},
		{name: "wildcard scope", apiKey: &models.APIKey{ID: uuid.New(), Scopes: []string{"*"}}},
		{name: "scope missing", apiKey: &models.APIKey{ID: uuid.New(), Scopes: []string{"keys:read"}}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.apiKey != nil {
				ctx = contextWithAPIKey(uuid.New(), tt.apiKey)
			}

			err := requireScope(ctx, scopeKeysSign)
			if tt.wantError {
				require.NotNil(t, err)
				assert.Equal(t, UnauthorizedError, err.Code)
				return
			}
			assert.Nil(t, err)
		})
	}
}

func TestResolveKey(t *testing.T) {
	const (
		boundAddr   = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
		foreignAddr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	)

	orgID := uuid.New()
	boundKey := &models.Key{ID: uuid.New(), OrgID: orgID}
	foreignKey := &models.Key{ID: uuid.New(), OrgID: orgID}

	newContext := func() context.Context {
		return contextWithAPIKey(orgID, &models.APIKey{
			ID:            uuid.New(),
			OrgID:         orgID,
			Scopes:        []string{"keys:sign"},
			AllowedKeyIDs: []uuid.UUID{boundKey.ID},
		})
	}

	t.Run("resolves a bound key", func(t *testing.T) {
		repo := new(MockKeyRepository)
		repo.On("GetByEthAddress", mock.Anything, orgID, boundAddr).Return(boundKey, nil)

		key, err := resolveKey(newContext(), repo, orgID, boundAddr)
		require.Nil(t, err)
		assert.Equal(t, boundKey.ID, key.ID)
	})

	t.Run("a key outside the binding is indistinguishable from an unknown one", func(t *testing.T) {
		repo := new(MockKeyRepository)
		repo.On("GetByEthAddress", mock.Anything, orgID, foreignAddr).Return(foreignKey, nil)

		_, boundErr := resolveKey(newContext(), repo, orgID, foreignAddr)
		require.NotNil(t, boundErr)

		unknownRepo := new(MockKeyRepository)
		unknownRepo.On("GetByEthAddress", mock.Anything, orgID, foreignAddr).Return(nil, nil)

		_, unknownErr := resolveKey(newContext(), unknownRepo, orgID, foreignAddr)
		require.NotNil(t, unknownErr)

		assert.Equal(t, ResourceNotFound, boundErr.Code)
		assert.Equal(t, unknownErr.Message, boundErr.Message)
		assert.Equal(t, unknownErr.Data, boundErr.Data)
	})

	t.Run("without a binding every key resolves", func(t *testing.T) {
		repo := new(MockKeyRepository)
		repo.On("GetByEthAddress", mock.Anything, orgID, foreignAddr).Return(foreignKey, nil)

		ctx := contextWithAPIKey(orgID, &models.APIKey{ID: uuid.New(), OrgID: orgID, Scopes: []string{"keys:sign"}})
		key, err := resolveKey(ctx, repo, orgID, foreignAddr)
		require.Nil(t, err)
		assert.Equal(t, foreignKey.ID, key.ID)
	})
}

func TestEthSignTransactionHandler_RejectsForeignFrom(t *testing.T) {
	orgID := uuid.New()
	foreignKey := &models.Key{ID: uuid.New(), OrgID: orgID}

	repo := new(MockKeyRepository)
	repo.On("GetByEthAddress", mock.Anything, orgID, mock.Anything).Return(foreignKey, nil)

	handler := &EthSignTransactionHandler{keyRepo: repo, baoClient: nil}

	ctx := contextWithAPIKey(orgID, &models.APIKey{
		ID:            uuid.New(),
		OrgID:         orgID,
		Scopes:        []string{"keys:sign"},
		AllowedKeyIDs: []uuid.UUID{uuid.New()},
	})
	params := `[{
		"from": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"to": "0x1234567890123456789012345678901234567890",
		"gas": "0x5208",
		"gasPrice": "0x3b9aca00",
		"value": "0x0",
		"nonce": "0x1",
		"chainId": "0xa"
	}]`
	_, err := handler.Handle(ctx, json.RawMessage(params))

	require.NotNil(t, err)
	assert.Equal(t, ResourceNotFound, err.Code)
}

func TestEthAccountsHandler_BoundAddresses(t *testing.T) {
	orgID := uuid.New()
	boundAddr := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	foreignAddr := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	boundKey := &models.Key{ID: uuid.New(), OrgID: orgID, EthAddress: &boundAddr}
	foreignKey := &models.Key{ID: uuid.New(), OrgID: orgID, EthAddress: &foreignAddr}

	t.Run("lists only bound addresses", func(t *testing.T) {
		repo := new(MockKeyRepository)
		repo.On("ListByOrg", mock.Anything, orgID).Return([]*models.Key{boundKey, foreignKey}, nil)
		handler := NewEthAccountsHandler(repo)

		ctx := contextWithAPIKey(orgID, &models.APIKey{
			ID:            uuid.New(),
			OrgID:         orgID,
			Scopes:        []string{"keys:read"},
			AllowedKeyIDs: []uuid.UUID{boundKey.ID},
		})
		result, err := handler.Handle(ctx, json.RawMessage(`[]`))

		require.Nil(t, err)
		assert.Equal(t, []string{boundAddr}, result)
		repo.AssertExpectations(t)
	})

	t.Run("requires the read scope", func(t *testing.T) {
		repo := new(MockKeyRepository)
		handler := NewEthAccountsHandler(repo)

		ctx := contextWithAPIKey(orgID, &models.APIKey{ID: uuid.New(), OrgID: orgID, Scopes: []string{"keys:sign"}})
		_, err := handler.Handle(ctx, json.RawMessage(`[]`))

		require.NotNil(t, err)
		assert.Equal(t, UnauthorizedError, err.Code)
	})
}
