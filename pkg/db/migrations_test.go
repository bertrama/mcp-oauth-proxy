package db

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func testDatabase(t *testing.T, dialect string) (string, *gorm.DB) {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "legacy.db")
	dialector := gorm.Dialector(sqlite.Open(dsn))
	if dialect == "postgres" {
		dsn = os.Getenv("MIGRATION_TEST_POSTGRES_DSN")
		if dsn == "" {
			dsn = os.Getenv("TEST_DATABASE_DSN")
		}

		if dsn == "" {
			t.Skip("PostgreSQL test DSN is not set")
		}

		base, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		require.NoError(t, err)

		baseConn, err := base.DB()
		require.NoError(t, err)

		schema := fmt.Sprintf("migration_test_%d", time.Now().UnixNano())
		require.NoError(t, base.Exec("CREATE SCHEMA "+schema).Error)

		t.Cleanup(func() { base.Exec("DROP SCHEMA " + schema + " CASCADE"); baseConn.Close() })
		parsed, err := url.Parse(dsn)
		require.NoError(t, err)

		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
		dialector = postgres.Open(dsn)
	}

	raw, err := gorm.Open(dialector, &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := raw.DB()
	require.NoError(t, err)

	t.Cleanup(func() { sqlDB.Close() })

	return dsn, raw
}

func legacyFixture(t *testing.T, dialect string) (string, *gorm.DB) {
	t.Helper()

	dsn, raw := testDatabase(t, dialect)
	ddl, err := os.ReadFile("testdata/legacy_" + dialect + ".sql")
	require.NoError(t, err)

	for _, statement := range strings.Split(string(ddl), ";") {
		if strings.TrimSpace(statement) != "" {
			require.NoError(t, raw.Exec(statement).Error)
		}
	}

	now := time.Now().UTC()
	require.NoError(t, raw.Exec("INSERT INTO clients (client_id, client_secret, redirect_uris) VALUES (?, ?, ?)", "client", "client-secret", `["https://client/callback"]`).Error)

	require.NoError(t, raw.Exec("INSERT INTO grants (id, client_id, user_id, scope, props, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)", "grant", "client", "user", `["openid"]`, `{"encrypted":false,"access_token":"upstream-secret","refresh_token":"upstream-refresh","user_id":"user"}`, now.Unix(), now.Add(time.Hour).Unix()).Error)

	require.NoError(t, raw.Exec("INSERT INTO authorization_codes (code, grant_id, user_id, expires_at) VALUES (?, ?, ?, ?)", "code", "grant", "user", now.Add(time.Minute)).Error)

	require.NoError(t, raw.Exec("INSERT INTO access_tokens (access_token, refresh_token, client_id, user_id, grant_id, expires_at, refresh_token_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)", hashToken("user:grant:access"), hashToken("user:grant:refresh"), "client", "user", "grant", now.Add(time.Hour), now.Add(24*time.Hour)).Error)

	for _, state := range []string{"revoked", "expired"} {
		expiry := now.Add(time.Hour)
		if state == "expired" {
			expiry = now.Add(-time.Hour)
		}

		require.NoError(t, raw.Exec("INSERT INTO access_tokens (access_token,refresh_token,client_id,user_id,grant_id,expires_at,refresh_token_expires_at,revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", hashToken("user:grant:"+state), hashToken("user:grant:"+state+"-refresh"), "client", "user", "grant", expiry, expiry, state == "revoked").Error)
	}

	return dsn, raw
}

func TestLegacyMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, raw := legacyFixture(t, dialect)

			// Reproduce the empty destination tables left by a failed upgrade.
			require.NoError(t, raw.AutoMigrate(&types.ClientInfo{}, &types.TokenData{}))

			store, err := New(dsn)
			require.NoError(t, err)

			defer store.Close()

			client, err := store.GetClient("client")
			require.NoError(t, err)
			require.Equal(t, "client-secret", client.ClientSecret)
			require.Equal(t, types.StringSlice{"https://client/callback"}, client.RedirectUris)

			token, err := store.GetToken("user:grant:access")
			require.NoError(t, err)
			require.Equal(t, hashToken("user:grant:access"), token.AccessToken)

			_, err = store.GetTokenByRefreshToken("user:grant:refresh")
			require.NoError(t, err)

			_, _, err = store.ValidateAuthCode("code")
			require.NoError(t, err)

			grant, err := store.GetGrant("grant", "user")
			require.NoError(t, err)
			require.Equal(t, types.JSON{"encrypted": false, "access_token": "upstream-secret", "refresh_token": "upstream-refresh", "user_id": "user"}, grant.Props)

			require.False(t, raw.Migrator().HasTable("clients"))
			require.False(t, raw.Migrator().HasTable("access_tokens"))

			second, err := New(dsn)
			require.NoError(t, err)

			defer second.Close()

			again, err := second.GetGrant("grant", "user")
			require.NoError(t, err)
			require.Equal(t, grant.Props, again.Props)

			manager, err := tokens.NewTokenManager(store)
			require.NoError(t, err)

			_, err = manager.GetTokenInfo("user:grant:access")
			require.NoError(t, err)

			for _, state := range []string{"revoked", "expired"} {
				_, err = manager.GetTokenInfo("user:grant:" + state)
				require.Error(t, err)
			}
		})
	}
}

func TestLegacyMigrationRollback(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, raw := legacyFixture(t, dialect)

			// Fail after clients has been renamed to prove earlier DDL rolls back.
			require.NoError(t, raw.AutoMigrate(&types.TokenData{}))
			require.NoError(t, raw.Create(&types.TokenData{AccessToken: "new-token", RefreshToken: "new-refresh", ClientID: "client", UserID: "user", GrantID: "grant", ExpiresAt: time.Now(), RefreshTokenExpiresAt: time.Now()}).Error)

			_, err := New(dsn)
			require.ErrorContains(t, err, "populated token_data")
			require.True(t, raw.Migrator().HasTable("clients"))
			require.True(t, raw.Migrator().HasTable("access_tokens"))
			require.False(t, raw.Migrator().HasTable("client_infos"))
			require.False(t, raw.Migrator().HasTable("proxy_migrations"))

			var props string
			require.NoError(t, raw.Raw("SELECT props FROM grants WHERE id = ?", "grant").Scan(&props).Error)
			require.Contains(t, props, "upstream-secret")
		})
	}
}

func TestLegacyMigrationConflict(t *testing.T) {
	dsn, raw := legacyFixture(t, "sqlite")
	require.NoError(t, raw.AutoMigrate(&types.ClientInfo{}))
	require.NoError(t, raw.Create(&types.ClientInfo{ClientID: "new-client"}).Error)

	_, err := New(dsn)
	require.ErrorContains(t, err, "populated client_infos")
	require.True(t, raw.Migrator().HasTable("clients"))
}

func TestMigrationConcurrentStartup(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, _ := legacyFixture(t, dialect)
			start := make(chan struct{})
			results := make(chan error, 4)

			for i := 0; i < 4; i++ {
				go func() {
					<-start
					store, err := New(dsn)
					if err == nil {
						err = store.Close()
					}

					results <- err
				}()
			}

			close(start)

			for i := 0; i < 4; i++ {
				require.NoError(t, <-results)
			}
		})
	}
}

func TestMigrationPreservesForeignKeys(t *testing.T) {
	dsn, raw := legacyFixture(t, "sqlite")
	store, err := New(dsn + "?_pragma=foreign_keys(1)")
	require.NoError(t, err)

	defer store.Close()

	var enabled int
	require.NoError(t, store.db.Raw("PRAGMA foreign_keys").Scan(&enabled).Error)
	require.Equal(t, 1, enabled)
	require.NoError(t, store.db.Exec("DELETE FROM grants WHERE id = ?", "grant").Error)

	var count int64
	require.NoError(t, raw.Table("token_data").Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, raw.Table("authorization_codes").Count(&count).Error)
	require.Zero(t, count)
}

func TestMigrationRejectsIncompleteSchema(t *testing.T) {
	dsn, raw := legacyFixture(t, "sqlite")
	require.NoError(t, raw.Exec("ALTER TABLE access_tokens DROP COLUMN refresh_token_expires_at").Error)

	_, err := New(dsn)
	require.ErrorContains(t, err, "missing access_tokens.refresh_token_expires_at")
	require.True(t, raw.Migrator().HasTable("clients"))
}

func TestMigrationPreservesGrantProperties(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	envelope, err := encryption.EncryptData(map[string]any{"access_token": "secret"}, key)
	require.NoError(t, err)

	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, raw := legacyFixture(t, dialect)
			props := types.JSON{"encrypted": true, "encrypted_data": envelope.Data, "iv": envelope.IV, "algorithm": envelope.Algorithm}
			require.NoError(t, raw.Table("grants").Where("id = ?", "grant").Update("props", props).Error)

			store, err := New(dsn)
			require.NoError(t, err)

			defer store.Close()

			grant, err := store.GetGrant("grant", "user")
			require.NoError(t, err)
			require.Equal(t, props, grant.Props)
		})
	}
}

func TestMigrationPreservesCurrentSchema(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, raw := testDatabase(t, dialect)
			original := &Store{db: raw, dbType: dialect}
			require.NoError(t, original.setupSchema())
			require.NoError(t, original.StoreClient(&types.ClientInfo{ClientID: "client"}))

			props := types.JSON{"access_token": "plaintext"}
			require.NoError(t, original.StoreGrant(&types.Grant{ID: "grant", ClientID: "client", UserID: "user", Props: props}))
			require.NoError(t, original.StoreToken(&types.TokenData{AccessToken: "user:grant:token", RefreshToken: "user:grant:refresh", ClientID: "client", UserID: "user", GrantID: "grant", ExpiresAt: time.Now().Add(time.Hour)}))

			for i := 0; i < 2; i++ {
				store, err := New(dsn)
				require.NoError(t, err)

				_, err = store.GetClient("client")
				require.NoError(t, err)

				_, err = store.GetToken("user:grant:token")
				require.NoError(t, err)

				grant, err := store.GetGrant("grant", "user")
				require.NoError(t, err)
				require.Equal(t, props, grant.Props)
				require.NoError(t, store.Close())
			}

			require.False(t, raw.Migrator().HasTable("clients"))
			require.False(t, raw.Migrator().HasTable("access_tokens"))
		})
	}
}

func TestMigrationPreservesDestinationDependencies(t *testing.T) {
	dsn, raw := legacyFixture(t, "postgres")
	require.NoError(t, raw.AutoMigrate(&types.ClientInfo{}))
	require.NoError(t, raw.Exec("CREATE VIEW registered_clients AS SELECT client_id FROM client_infos").Error)

	_, err := New(dsn)
	require.ErrorContains(t, err, "depend")

	require.True(t, raw.Migrator().HasTable("clients"))
	require.True(t, raw.Migrator().HasTable("client_infos"))
	require.False(t, raw.Migrator().HasTable("proxy_migrations"))

	var count int64
	require.NoError(t, raw.Table("registered_clients").Count(&count).Error)
	require.Zero(t, count)
}

func TestMigrationSkipsNullRefreshExpiration(t *testing.T) {
	dsn, raw := legacyFixture(t, "sqlite")
	require.NoError(t, raw.Exec(`INSERT INTO access_tokens
		(access_token, refresh_token, client_id, user_id, grant_id, expires_at, refresh_token_expires_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		hashToken("user:grant:null-access"), hashToken("user:grant:null-refresh"),
		"client", "user", "grant", time.Now().Add(time.Hour)).Error)

	store, err := New(dsn)
	require.NoError(t, err)
	defer store.Close()

	_, err = store.GetToken("user:grant:null-access")
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	_, err = store.GetTokenByRefreshToken("user:grant:null-refresh")
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	_, err = store.GetToken("user:grant:access")
	require.NoError(t, err)

	_, err = store.GetTokenByRefreshToken("user:grant:refresh")
	require.NoError(t, err)

	var remaining int64
	require.NoError(t, raw.Table("token_data").Count(&remaining).Error)
	require.EqualValues(t, 3, remaining)

	second, err := New(dsn)
	require.NoError(t, err)
	defer second.Close()

	_, err = second.GetToken("user:grant:null-access")
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	_, err = second.GetToken("user:grant:access")
	require.NoError(t, err)
}

func TestMigrationRenamesPostgresIndexes(t *testing.T) {
	for _, missingIndex := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_index=%t", missingIndex), func(t *testing.T) {
			dsn, raw := legacyFixture(t, "postgres")
			columns := []string{"client_id", "expires_at", "revoked"}

			if missingIndex {
				require.NoError(t, raw.Exec("DROP INDEX idx_access_tokens_revoked").Error)
			}

			// Capture the final index IDs after the first startup to verify
			// that the second startup leaves them intact.
			originalIDs := map[string]int64{}

			// A failed upgrade may have already created empty destination tables
			// and their indexes. Those must not conflict with the renamed indexes.
			require.NoError(t, raw.AutoMigrate(&types.ClientInfo{}, &types.TokenData{}))

			for attempt := 0; attempt < 2; attempt++ {
				store, err := New(dsn)
				require.NoError(t, err)
				require.NoError(t, store.Close())

				for _, column := range columns {
					require.False(t, raw.Migrator().HasIndex("token_data", "idx_access_tokens_"+column))
					require.True(t, raw.Migrator().HasIndex("token_data", "idx_token_data_"+column))

					var id int64
					require.NoError(t, raw.Raw("SELECT to_regclass(?)::oid::bigint", "idx_token_data_"+column).Scan(&id).Error)
					if originalID, exists := originalIDs[column]; exists {
						require.Equal(t, originalID, id)
					} else {
						require.NotZero(t, id)
						originalIDs[column] = id
					}
				}

				var count int64
				require.NoError(t, raw.Raw("SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'token_data'").Scan(&count).Error)
				require.EqualValues(t, 5, count) // Primary key, refresh-token uniqueness, and three lookup indexes.
			}
		})
	}
}

func TestPostgresIndexRenamePreservesIndex(t *testing.T) {
	_, raw := legacyFixture(t, "postgres")
	columns := []string{"client_id", "expires_at", "revoked"}
	originalIDs := map[string]int64{}
	for _, column := range columns {
		var id int64
		require.NoError(t, raw.Raw("SELECT to_regclass(?)::oid::bigint", "idx_access_tokens_"+column).Scan(&id).Error)
		require.NotZero(t, id)
		originalIDs[column] = id
	}

	require.NoError(t, raw.Migrator().RenameTable("clients", "client_infos"))
	require.NoError(t, raw.Migrator().RenameTable("access_tokens", "token_data"))
	require.NoError(t, raw.Transaction(migrateLegacyPostgres))

	for _, column := range columns {
		var id int64
		require.NoError(t, raw.Raw("SELECT to_regclass(?)::oid::bigint", "idx_token_data_"+column).Scan(&id).Error)
		require.Equal(t, originalIDs[column], id)
	}
}

func TestCompletedMigrationIgnoresLegacyTables(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dsn, raw := legacyFixture(t, dialect)
			store, err := New(dsn)
			require.NoError(t, err)
			require.NoError(t, store.Close())

			// Check both a single reappearing table and both legacy tables.
			for _, table := range []string{"clients", "access_tokens"} {
				require.NoError(t, raw.Exec("CREATE TABLE "+table+" (marker TEXT)").Error)
				require.NoError(t, raw.Exec("INSERT INTO "+table+" (marker) VALUES (?)", "legacy-only").Error)

				reopened, err := New(dsn)
				require.NoError(t, err)

				client, err := reopened.GetClient("client")
				require.NoError(t, err)
				require.Equal(t, "client-secret", client.ClientSecret)

				_, err = reopened.GetToken("user:grant:access")
				require.NoError(t, err)
				require.NoError(t, reopened.Close())

				var marker string
				require.NoError(t, raw.Table(table).Select("marker").Scan(&marker).Error)
				require.Equal(t, "legacy-only", marker)
			}
		})
	}
}
