-- Schema from legacy commit 4240ddd, including its refresh-expiration migration.
CREATE TABLE IF NOT EXISTS clients (
				client_id TEXT PRIMARY KEY,
				client_secret TEXT,
				redirect_uris TEXT NOT NULL,
				client_name TEXT,
				logo_uri TEXT,
				client_uri TEXT,
				policy_uri TEXT,
				tos_uri TEXT,
				jwks_uri TEXT,
				contacts TEXT,
				grant_types TEXT,
				response_types TEXT,
				registration_date INTEGER,
				token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic'
			);
CREATE TABLE IF NOT EXISTS grants (
				id TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				scope TEXT NOT NULL,
				metadata TEXT,
				props TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				code_challenge TEXT,
				code_challenge_method TEXT
			);
CREATE TABLE IF NOT EXISTS authorization_codes (
				code TEXT PRIMARY KEY,
				grant_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				expires_at DATETIME NOT NULL,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			);
CREATE TABLE IF NOT EXISTS access_tokens (
				access_token TEXT PRIMARY KEY,
				refresh_token TEXT UNIQUE,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				grant_id TEXT NOT NULL,
				scope TEXT,
				expires_at DATETIME NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				revoked INTEGER DEFAULT 0,
				revoked_at DATETIME,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_revoked ON access_tokens(revoked);
CREATE INDEX IF NOT EXISTS idx_grants_user_id ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_client_id ON grants(client_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
ALTER TABLE access_tokens ADD COLUMN refresh_token_expires_at DATETIME;
