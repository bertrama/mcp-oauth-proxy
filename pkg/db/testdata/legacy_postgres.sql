-- Schema from legacy commit 4240ddd, including its refresh-expiration migration.
CREATE TABLE IF NOT EXISTS clients (
				client_id VARCHAR(255) PRIMARY KEY,
				client_secret VARCHAR(255),
				redirect_uris JSONB NOT NULL,
				client_name VARCHAR(255),
				logo_uri VARCHAR(500),
				client_uri VARCHAR(500),
				policy_uri VARCHAR(500),
				tos_uri VARCHAR(500),
				jwks_uri VARCHAR(500),
				contacts JSONB,
				grant_types JSONB,
				response_types JSONB,
				registration_date BIGINT,
				token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic'
			);
CREATE TABLE IF NOT EXISTS grants (
				id VARCHAR(255) PRIMARY KEY,
				client_id VARCHAR(255) NOT NULL,
				user_id VARCHAR(255) NOT NULL,
				scope JSONB NOT NULL,
				metadata JSONB,
				props JSONB,
				created_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				code_challenge VARCHAR(255),
				code_challenge_method VARCHAR(10)
			);
CREATE TABLE IF NOT EXISTS authorization_codes (
				code VARCHAR(255) PRIMARY KEY,
				grant_id VARCHAR(255) NOT NULL,
				user_id VARCHAR(255) NOT NULL,
				expires_at TIMESTAMPTZ NOT NULL,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			);
CREATE TABLE IF NOT EXISTS access_tokens (
				access_token VARCHAR(255) PRIMARY KEY,
				refresh_token VARCHAR(255) UNIQUE,
				client_id VARCHAR(255) NOT NULL,
				user_id VARCHAR(255) NOT NULL,
				grant_id VARCHAR(255) NOT NULL,
				scope TEXT,
				expires_at TIMESTAMPTZ NOT NULL,
				created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
				revoked BOOLEAN DEFAULT FALSE,
				revoked_at TIMESTAMPTZ,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_revoked ON access_tokens(revoked);
CREATE INDEX IF NOT EXISTS idx_grants_user_id ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_client_id ON grants(client_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
ALTER TABLE access_tokens ADD COLUMN refresh_token_expires_at TIMESTAMPTZ;
ALTER TABLE access_tokens ALTER COLUMN refresh_token_expires_at SET NOT NULL;
