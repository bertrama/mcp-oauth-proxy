package token

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type refreshTokenStore struct {
	client      *types.ClientInfo
	grant       *types.Grant
	refreshData *types.TokenData
	stored      *types.TokenData
	revoked     string
}

func (f *refreshTokenStore) GetClient(string) (*types.ClientInfo, error) { return f.client, nil }
func (f *refreshTokenStore) StoreToken(token *types.TokenData) error {
	f.stored = token
	return nil
}
func (f *refreshTokenStore) ValidateAuthCode(string) (string, string, error) { return "", "", nil }
func (f *refreshTokenStore) GetGrant(string, string) (*types.Grant, error)   { return f.grant, nil }
func (f *refreshTokenStore) DeleteAuthCode(string) error                     { return nil }
func (f *refreshTokenStore) GetTokenByRefreshToken(string) (*types.TokenData, error) {
	return f.refreshData, nil
}
func (f *refreshTokenStore) RevokeToken(token string) error {
	f.revoked = token
	return nil
}

func TestRefreshTokenRotationRevokesOldToken(t *testing.T) {
	store := &refreshTokenStore{
		client: &types.ClientInfo{ClientID: "client", TokenEndpointAuthMethod: "none"},
		grant:  &types.Grant{ID: "grant", ClientID: "client", UserID: "user"},
		refreshData: &types.TokenData{
			ClientID:              "client",
			UserID:                "user",
			GrantID:               "grant",
			Scope:                 "repo",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		},
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"client"},
		"refresh_token": {"old-refresh-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	NewHandler(store).ServeHTTP(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.NotNil(t, store.stored)
	assert.NotEqual(t, "old-refresh-token", store.stored.RefreshToken)
	assert.Equal(t, "old-refresh-token", store.revoked)
	assert.NotEqual(t, store.stored.RefreshToken, store.revoked)
}
