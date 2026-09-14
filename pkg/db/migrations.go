package db

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// postgresMigrationLockID is an arbitrary advisory-lock key shared by all proxy
// instances to serialize database migrations. Keep it stable across releases so
// instances starting different versions still acquire the same lock.
const postgresMigrationLockID int64 = 782347239101

// migrate pins a connection so SQLite pragmas and the transaction share state.
// Old application instances must be stopped before migration starts.
func (d *Store) migrate() error {
	return d.db.Connection(func(conn *gorm.DB) error {
		conn = conn.Session(&gorm.Session{NewDB: true})
		switch d.dbType {
		case "sqlite":
			return migrateSQLite(conn)
		case "postgres":
			return migratePostgres(conn)
		default:
			return fmt.Errorf("unsupported database type: %s", d.dbType)
		}
	})
}

// migrateSQLite runs migration on a pinned connection with temporary PRAGMA settings.
// Foreign key enforcement is disabled before the transaction because SQLite table
// rebuilds drop and replace tables, which could otherwise trigger cascading deletes
// or constraint failures. Changing foreign_keys inside a transaction has no effect.
// Before committing, foreign_key_check verifies that the rebuilt tables still have
// valid references; any violation rolls the migration back.
//
// busy_timeout gives concurrent startups up to 60 seconds to acquire SQLite's write
// lock instead of failing immediately while another migration holds it. Both settings
// are connection-specific, so their original values are read and restored on success
// or failure before the pinned connection returns to the pool.
func migrateSQLite(conn *gorm.DB) (resultErr error) {
	var foreignKeys, busyTimeout int
	if err := conn.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil {
		return err
	}
	if err := conn.Raw("PRAGMA busy_timeout").Scan(&busyTimeout).Error; err != nil {
		return err
	}
	if err := conn.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, conn.Exec(fmt.Sprintf("PRAGMA foreign_keys = %d", foreignKeys)).Error)
	}()
	if err := conn.Exec("PRAGMA busy_timeout = 60000").Error; err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, conn.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeout)).Error)
	}()
	// SQLite transactions use BEGIN IMMEDIATE to lock before reads.
	return conn.Transaction(func(tx *gorm.DB) (transactionErr error) {
		tx = tx.Session(&gorm.Session{NewDB: true})
		if err := migrateSchema(tx, "sqlite"); err != nil {
			return err
		}
		rows, err := tx.Raw("PRAGMA foreign_key_check").Rows()
		if err != nil {
			return err
		}
		defer func() { transactionErr = errors.Join(transactionErr, rows.Close()) }()
		if rows.Next() {
			return fmt.Errorf("migration would leave invalid foreign key references")
		}
		return rows.Err()
	})
}

func migratePostgres(conn *gorm.DB) error {
	return conn.Transaction(func(tx *gorm.DB) error {
		tx = tx.Session(&gorm.Session{NewDB: true})
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", postgresMigrationLockID).Error; err != nil {
			return err
		}
		return migrateSchema(tx, "postgres")
	})
}

func migrateSchema(tx *gorm.DB, dialect string) error {
	if err := tx.Exec("CREATE TABLE IF NOT EXISTS proxy_migrations (name TEXT PRIMARY KEY)").Error; err != nil {
		return err
	}
	if err := migrateLegacy(tx, dialect); err != nil {
		return err
	}
	if err := (&Store{db: tx, dbType: dialect}).setupSchema(); err != nil {
		return err
	}
	return nil
}

func migrationDone(tx *gorm.DB, name string) (bool, error) {
	var count int64
	err := tx.Table("proxy_migrations").Where("name = ?", name).Count(&count).Error
	return count != 0, err
}

func migrateLegacy(tx *gorm.DB, dialect string) error {
	const name = "legacy_4240ddd"
	// Once recorded, the current tables are authoritative. Ignore legacy tables
	// that remain or reappear rather than attempting to import their data again.
	done, err := migrationDone(tx, name)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	legacyClients := tx.Migrator().HasTable("clients")
	legacyTokens := tx.Migrator().HasTable("access_tokens")
	// Both legacy tables must be present to migrate. Neither is expected for a
	// fresh database or one already using the current schema without a ledger.
	if legacyClients != legacyTokens {
		return fmt.Errorf("incomplete legacy schema: expected both clients and access_tokens")
	}
	if !legacyClients {
		// Record that this database already uses the current schema. The entry
		// commits only if the caller's remaining schema changes also succeed.
		return tx.Exec("INSERT INTO proxy_migrations (name) VALUES (?)", name).Error
	}

	if err := validateLegacyColumns(tx); err != nil {
		return err
	}

	// Rename the legacy tables to the names used by GORM. Empty destinations
	// left by a failed upgrade can be replaced; populated ones require manual
	// reconciliation so newer client or session state is not overwritten.
	for _, pair := range [][2]string{{"clients", "client_infos"}, {"access_tokens", "token_data"}} {
		if tx.Migrator().HasTable(pair[1]) {
			var count int64
			if err := tx.Table(pair[1]).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("both %s and populated %s exist; reconcile before upgrading", pair[0], pair[1])
			}
			// Avoid GORM's PostgreSQL DROP TABLE CASCADE: unexpected dependencies
			// must abort migration rather than be removed with the empty table.
			if err := tx.Exec("DROP TABLE ?", clause.Table{Name: pair[1]}).Error; err != nil {
				return err
			}
		}
		if err := tx.Migrator().RenameTable(pair[0], pair[1]); err != nil {
			return err
		}
	}
	// Normalize backend-specific constraints and column types before the
	// caller runs AutoMigrate against the renamed tables.
	switch dialect {
	case "sqlite":
		if err := migrateLegacySQLite(tx); err != nil {
			return err
		}
	case "postgres":
		if err := migrateLegacyPostgres(tx); err != nil {
			return err
		}
	}
	// Record completion in the same transaction as the schema changes.
	return tx.Exec("INSERT INTO proxy_migrations (name) VALUES (?)", name).Error
}

// validateLegacyColumns checks the known legacy tables and columns before renaming
// or rebuilding them, rejecting unsupported columns that a rebuild would discard.
func validateLegacyColumns(tx *gorm.DB) error {
	required := map[string][]string{
		"clients":             {"client_id", "client_secret", "redirect_uris", "client_name", "logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri", "contacts", "grant_types", "response_types", "registration_date", "token_endpoint_auth_method"},
		"access_tokens":       {"access_token", "refresh_token", "client_id", "user_id", "grant_id", "scope", "expires_at", "refresh_token_expires_at", "created_at", "revoked", "revoked_at"},
		"grants":              {"id", "client_id", "user_id", "scope", "metadata", "props", "created_at", "expires_at", "code_challenge", "code_challenge_method"},
		"authorization_codes": {"code", "grant_id", "user_id", "expires_at"},
	}
	for table, columns := range required {
		if !tx.Migrator().HasTable(table) {
			return fmt.Errorf("unsupported legacy schema: missing table %s", table)
		}
		actual, err := tx.Migrator().ColumnTypes(table)
		if err != nil {
			return err
		}
		found := map[string]bool{}
		for _, column := range actual {
			found[column.Name()] = true
		}

		// The SQLite rebuilds copy an explicit set of columns. Reject unknown
		// columns rather than silently losing data, but allow created_at from
		// a previous AutoMigrate attempt.
		if table == "access_tokens" || table == "authorization_codes" {
			allowed := map[string]bool{"created_at": true}
			for _, column := range columns {
				allowed[column] = true
			}
			for column := range found {
				if !allowed[column] {
					return fmt.Errorf("unsupported legacy column %s.%s", table, column)
				}
			}
		}
		for _, column := range columns {
			if !found[column] {
				return fmt.Errorf("unsupported legacy schema: missing %s.%s", table, column)
			}
		}
	}
	return nil
}

func migrateLegacySQLite(tx *gorm.DB) error {
	// An interrupted legacy backfill can leave refresh expiration unset. Skip
	// those token rows rather than block every session's migration or invent a
	// new lifetime. Affected clients must authenticate again.
	// The SQLite migrator misparses unnamed legacy FOREIGN KEY clauses
	// as columns. Rebuild these two tables explicitly with named constraints.
	authCodeCopy := `INSERT INTO authorization_codes_migration (code, grant_id, user_id, expires_at) SELECT code, grant_id, user_id, expires_at FROM authorization_codes`
	if tx.Migrator().HasColumn("authorization_codes", "created_at") {
		authCodeCopy = `INSERT INTO authorization_codes_migration SELECT code, grant_id, user_id, expires_at, created_at FROM authorization_codes`
	}
	for _, statement := range []string{
		`CREATE TABLE token_data_migration (
     access_token text PRIMARY KEY, refresh_token text, client_id text NOT NULL,
     user_id text NOT NULL, grant_id text NOT NULL, scope text, expires_at datetime NOT NULL,
     refresh_token_expires_at datetime NOT NULL, created_at datetime, revoked numeric DEFAULT false,
     revoked_at datetime, CONSTRAINT fk_token_data_grant FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE)`,
		`INSERT INTO token_data_migration SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at, created_at, revoked, revoked_at FROM token_data WHERE refresh_token_expires_at IS NOT NULL`,
		`DROP TABLE token_data`,
		`ALTER TABLE token_data_migration RENAME TO token_data`,
		`CREATE TABLE authorization_codes_migration (code text PRIMARY KEY, grant_id text NOT NULL,
     user_id text NOT NULL, expires_at datetime NOT NULL, created_at datetime,
     CONSTRAINT fk_authorization_codes_grant FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE)`,
		authCodeCopy,
		`DROP TABLE authorization_codes`,
		`ALTER TABLE authorization_codes_migration RENAME TO authorization_codes`,
	} {
		if err := tx.Exec(statement).Error; err != nil {
			return err
		}
	}
	return nil
}

func migrateLegacyPostgres(tx *gorm.DB) error {
	// Table renames retain index names. Reuse the legacy indexes under the names
	// GORM expects so AutoMigrate does not create duplicate indexes.
	for _, column := range []string{"client_id", "expires_at", "revoked"} {
		oldName := "idx_access_tokens_" + column
		newName := "idx_token_data_" + column
		if tx.Migrator().HasIndex("token_data", oldName) {
			if err := tx.Migrator().RenameIndex("token_data", oldName, newName); err != nil {
				return err
			}
		}
	}

	// GORM expects this name when replacing the legacy UNIQUE constraint
	// with its current unique index.
	if tx.Migrator().HasConstraint("token_data", "access_tokens_refresh_token_key") {
		if err := tx.Exec("ALTER TABLE token_data RENAME CONSTRAINT access_tokens_refresh_token_key TO uni_token_data_refresh_token").Error; err != nil {
			return err
		}
	}
	for table, columns := range map[string][]string{
		"client_infos": {"redirect_uris", "contacts", "grant_types", "response_types"},
		"grants":       {"scope", "metadata", "props"},
	} {
		for _, column := range columns {
			// Identifiers are fixed migration constants, never external input.
			if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s TYPE text USING %s::text", table, column, column)).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
