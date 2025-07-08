// Copyright 2025 Paddy Lindsay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
