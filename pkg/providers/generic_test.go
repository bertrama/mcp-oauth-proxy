package providers

import (
	"net/http"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestGenericProvider_MicrosoftAuthorizationURL(t *testing.T) {
	provider := &GenericProvider{
		authorizeURL: "https://login.microsoftonline.com/example-tenant/oauth2/v2.0/authorize",
		metadata: &types.OAuthMetadata{
			AuthorizationEndpoint: "https://login.microsoftonline.com/example-tenant/oauth2/v2.0/authorize",
		},
	}

	authURL := provider.GetAuthorizationURLWithPKCE(
		"test_client",
		"https://test.example.com/callback",
		"openid offline_access Group.Read.All Group.ReadWrite.All",
		"test_state",
		"test_challenge",
	)

	assert.Contains(t, authURL, "prompt=select_account")
	assert.Contains(t, authURL, "access_type=offline")
	assert.Contains(t, authURL, "code_challenge=")
	assert.Contains(t, authURL, "code_challenge_method=S256")
	assert.Contains(t, authURL, "scope=openid+offline_access+Group.Read.All+Group.ReadWrite.All")
}

func TestGenericProvider_RefreshTokenParams(t *testing.T) {
	t.Run("TestGoogleRefreshTokenParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "openid profile email", "test_state")

		assert.Contains(t, authURL, "access_type=offline")
		assert.Contains(t, authURL, "prompt=consent")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=openid+profile+email")
		assert.Contains(t, authURL, "state=test_state")
	})

	t.Run("TestGenericProviderNoSpecialParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://github.com/login/oauth/authorize",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "read:user user:email", "test_state")

		// Should not contain Google or Microsoft specific parameters
		assert.NotContains(t, authURL, "response_mode=query")
		assert.NotContains(t, authURL, "offline_access")
		assert.NotContains(t, authURL, "prompt=")

		// Should contain standard OAuth parameters
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=read%3Auser+user%3Aemail")
		assert.Contains(t, authURL, "state=test_state")
	})
}
