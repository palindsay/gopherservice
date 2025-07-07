// Package database provides database connectivity and schema management.
package database

import (
	"database/sql"
	"fmt"

	_ "github.com/glebarez/go-sqlite" // SQLite driver
)

// New creates a new database connection and ensures the schema is up to date.
func New(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := migrateSchema(db); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	return db, nil
}

// migrateSchema creates the necessary tables if they don't exist.
func migrateSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			full_name TEXT NOT NULL,
			roles TEXT NOT NULL,
			is_active BOOLEAN NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			last_login_at DATETIME
		);

		CREATE TABLE IF NOT EXISTS passwords (
			user_id TEXT PRIMARY KEY,
			hash TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);
	`)
	return err
}
