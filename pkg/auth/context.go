// Copyright 2025 Phillip Lindsay
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

// Package auth provides JWT-based authentication and authorization functionality.
package auth

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ClaimsKey is the context key for JWT claims.
	ClaimsKey = contextKey("claims")
	// UserIDKey is the context key for the user ID.
	UserIDKey = contextKey("user_id")
)
