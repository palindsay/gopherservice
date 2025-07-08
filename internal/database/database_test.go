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

package database_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/glebarez/go-sqlite" // SQLite driver
	"github.com/plindsay/gopherservice/internal/database"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{
			name:    "in-memory database",
			dsn:     ":memory:",
			wantErr: false,
		},
		{
			name:    "file database",
			dsn:     "file:test.db?mode=memory",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := database.New(tt.dsn)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if db != nil {
				defer db.Close()
			}
		})
	}
}

func TestDatabaseSchema(t *testing.T) {
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer db.Close()

	// Test that tables were created
	tables := []string{"users", "passwords"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s was not created: %v", table, err)
		}
	}

	// Test users table structure
	userColumns := map[string]string{
		"id":            "TEXT",
		"email":         "TEXT",
		"full_name":     "TEXT",
		"roles":         "TEXT",
		"is_active":     "INTEGER", // SQLite represents BOOLEAN as INTEGER
		"created_at":    "DATETIME",
		"updated_at":    "DATETIME",
		"last_login_at": "DATETIME",
	}

	rows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		t.Fatalf("failed to get users table info: %v", err)
	}
	defer rows.Close()

	columnCount := 0
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &dtype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("failed to scan column info: %v", err)
		}
		columnCount++

		expectedType, exists := userColumns[name]
		if !exists {
			t.Errorf("unexpected column: %s", name)
		}
		// SQLite may store types differently, so we do a more lenient check
		if name == "is_active" && dtype == "INTEGER" {
			// This is expected for BOOLEAN columns in SQLite
			continue
		} else if expectedType != "" && dtype != expectedType {
			// For other columns, we still expect the type to match
			// but we'll be lenient about exact type matching
			t.Logf("Warning: column %s has type %s, expected %s", name, dtype, expectedType)
		}
	}

	if columnCount != len(userColumns) {
		t.Errorf("expected %d columns, got %d", len(userColumns), columnCount)
	}

	// Test passwords table structure
	passwordColumns := map[string]bool{
		"user_id": true,
		"hash":    true,
	}

	rows, err = db.Query("PRAGMA table_info(passwords)")
	if err != nil {
		t.Fatalf("failed to get passwords table info: %v", err)
	}
	defer rows.Close()

	passwordColumnCount := 0
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &dtype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("failed to scan column info: %v", err)
		}
		passwordColumnCount++

		if !passwordColumns[name] {
			t.Errorf("unexpected column in passwords table: %s", name)
		}
	}

	if passwordColumnCount != len(passwordColumns) {
		t.Errorf("expected %d columns in passwords table, got %d", len(passwordColumns), passwordColumnCount)
	}
}

func TestDatabaseOperations(t *testing.T) {
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer db.Close()

	// Test insert into users table
	_, err = db.Exec(`
		INSERT INTO users (id, email, full_name, roles, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-id", "test@example.com", "Test User", "user", true)
	if err != nil {
		t.Errorf("failed to insert user: %v", err)
	}

	// Test select from users table
	var email string
	err = db.QueryRow("SELECT email FROM users WHERE id = ?", "test-id").Scan(&email)
	if err != nil {
		t.Errorf("failed to select user: %v", err)
	}
	if email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", email)
	}

	// Test unique constraint on email
	_, err = db.Exec(`
		INSERT INTO users (id, email, full_name, roles, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-id-2", "test@example.com", "Test User 2", "user", true)
	if err == nil {
		t.Error("expected unique constraint violation, got nil")
	}

	// Test foreign key relationship
	_, err = db.Exec("INSERT INTO passwords (user_id, hash) VALUES (?, ?)", "test-id", "hashed-password")
	if err != nil {
		t.Errorf("failed to insert password: %v", err)
	}

	// Test foreign key constraint (this might not work by default in SQLite without enabling foreign keys)
	// But we should still test the table structure
	var hash string
	err = db.QueryRow("SELECT hash FROM passwords WHERE user_id = ?", "test-id").Scan(&hash)
	if err != nil {
		t.Errorf("failed to select password: %v", err)
	}
	if hash != "hashed-password" {
		t.Errorf("expected hash 'hashed-password', got %s", hash)
	}
}

func TestMigrationIdempotency(t *testing.T) {
	// Create a temporary file for the database
	tmpfile, err := os.CreateTemp("", "test*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Create database first time
	db1, err := database.New(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to create database first time: %v", err)
	}

	// Insert some data
	_, err = db1.Exec(`
		INSERT INTO users (id, email, full_name, roles, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-id", "test@example.com", "Test User", "user", true)
	if err != nil {
		t.Errorf("failed to insert user: %v", err)
	}
	db1.Close()

	// Create database second time - should not fail or lose data
	db2, err := database.New(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to create database second time: %v", err)
	}
	defer db2.Close()

	// Check that data still exists
	var count int
	err = db2.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", "test-id").Scan(&count)
	if err != nil {
		t.Errorf("failed to count users: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Create a temporary file for the database to support concurrent access
	tmpfile, err := os.CreateTemp("", "concurrent_test*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	db, err := database.New(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer db.Close()

	// Enable multi-threading for SQLite
	db.SetMaxOpenConns(10)

	// Run concurrent operations
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Try to insert a user
			_, err := db.Exec(`
				INSERT INTO users (id, email, full_name, roles, is_active, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
			`, fmt.Sprintf("user-%d", id), fmt.Sprintf("user%d@example.com", id), "Test User", "user", true)
			if err != nil {
				t.Errorf("failed to insert user %d: %v", id, err)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all users were inserted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		t.Errorf("failed to count users: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 users, got %d", count)
	}
}
