package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/db"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func refresh(t *testing.T, h http.Handler, clientID, refreshToken string) (int, types.TokenResponse) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshToken}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp types.TokenResponse
	t.Logf("refresh -> %d %s", w.Code, strings.TrimSpace(w.Body.String()))
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	}
	return w.Code, resp
}

// Regression: the refresh grant used to revoke the refresh token it had just
// issued (the variable was reassigned before RevokeToken), so the first refresh
// produced a token pair that was already revoked and the connection died about
// an hour after it was made.
func TestRefreshGrantKeepsNewTokensAndRetiresOldOnes(t *testing.T) {
	t.Chdir(t.TempDir())
	store, err := db.New("")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "c1", TokenEndpointAuthMethod: "none"}))
	require.NoError(t, store.StoreGrant(&types.Grant{
		ID: "g1", ClientID: "c1", UserID: "u1", Scope: []string{"openid"},
		CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}))
	const original = "u1:g1:original-refresh"
	require.NoError(t, store.StoreToken(&types.TokenData{
		AccessToken: "u1:g1:original-access", RefreshToken: original, ClientID: "c1", UserID: "u1", GrantID: "g1",
		ExpiresAt: time.Now().Add(time.Hour), RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	h := NewHandler(store)

	code, first := refresh(t, h, "c1", original)
	require.Equal(t, http.StatusOK, code)

	newAccess, err := store.GetToken(first.AccessToken)
	require.NoError(t, err)
	assert.False(t, newAccess.Revoked, "the access token just issued must be usable")

	oldRow, err := store.GetTokenByRefreshToken(original)
	require.NoError(t, err)
	assert.True(t, oldRow.Revoked, "the refresh token that was just spent must be retired")

	code, second := refresh(t, h, "c1", first.RefreshToken)
	assert.Equal(t, http.StatusOK, code, "the refresh token from the first refresh must work for the second")
	assert.NotEmpty(t, second.AccessToken)

	code, _ = refresh(t, h, "c1", original)
	assert.Equal(t, http.StatusUnauthorized, code, "a spent refresh token must not work twice")
}
