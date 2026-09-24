package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/db"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenGrantRevokesOldTokenNotNewToken(t *testing.T) {
	store, err := db.New(filepath.Join(t.TempDir(), "oauth_proxy.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = store.Close()
	})

	const (
		clientID = "test_client"
		userID   = "test_user"
		grantID  = "test_grant"
	)

	require.NoError(t, store.StoreClient(&types.ClientInfo{
		ClientID:                clientID,
		RedirectUris:            []string{"http://localhost:8080/callback"},
		TokenEndpointAuthMethod: "none",
	}))
	require.NoError(t, store.StoreGrant(&types.Grant{
		ID:        grantID,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     []string{"read"},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))

	oldAccessToken := userID + ":" + grantID + ":old_access_secret"
	oldRefreshToken := userID + ":" + grantID + ":old_refresh_secret"
	require.NoError(t, store.StoreToken(&types.TokenData{
		AccessToken:           oldAccessToken,
		RefreshToken:          oldRefreshToken,
		ClientID:              clientID,
		UserID:                userID,
		GrantID:               grantID,
		Scope:                 "read",
		ExpiresAt:             time.Now().Add(time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {oldRefreshToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	NewHandler(store).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp types.TokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEqual(t, oldRefreshToken, resp.RefreshToken)

	// The newly issued token must remain usable.
	newToken, err := store.GetToken(resp.AccessToken)
	require.NoError(t, err)
	assert.False(t, newToken.Revoked, "newly issued access token should not be revoked")

	newRefresh, err := store.GetTokenByRefreshToken(resp.RefreshToken)
	require.NoError(t, err)
	assert.False(t, newRefresh.Revoked, "newly issued refresh token should not be revoked")

	// The refresh token that was exchanged must no longer be usable.
	oldToken, err := store.GetTokenByRefreshToken(oldRefreshToken)
	require.NoError(t, err)
	assert.True(t, oldToken.Revoked, "exchanged refresh token should be revoked")
}
