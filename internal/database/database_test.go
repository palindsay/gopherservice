//go:build sqlite

// Package database_test provides tests for the database package.
package database_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/plindsay/gopherservice/internal/database"
	_ "modernc.org/sqlite" // SQLite driver
)

func TestNew(t *testing.T) {
	db, err := database.New(":memory:")
	require.NoError(t, err)
	require.NotNil(t, db)
	defer db.Close()

	err = db.Ping()
	require.NoError(t, err)
}
