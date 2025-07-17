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

// Package security provides comprehensive security middleware for HTTP and gRPC services.
//
// This package implements production-ready security patterns including rate limiting,
// CORS handling, security headers, request validation, and protection against common
// web vulnerabilities following OWASP guidelines.
package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SecurityConfig holds configuration for security middleware.
type SecurityConfig struct { // nolint: revive
	// Rate limiting configuration
	RateLimit *RateLimitConfig `yaml:"rate_limit"`

	// CORS configuration
	CORS *CORSConfig `yaml:"cors"`

	// Security headers configuration
	SecurityHeaders *SecurityHeadersConfig `yaml:"security_headers"`

	// Request validation configuration
	RequestValidation *RequestValidationConfig `yaml:"request_validation"`

	// IP allowlist/blocklist configuration
	IPFiltering *IPFilteringConfig `yaml:"ip_filtering"`
}

// RateLimitConfig configures rate limiting behavior.
type RateLimitConfig struct {
	// Enable rate limiting
	Enabled bool `yaml:"enabled"`

	// Requests per second per IP
	RequestsPerSecond float64 `yaml:"requests_per_second"`

	// Burst capacity
	BurstSize int `yaml:"burst_size"`

	// Rate limit by user ID instead of IP
	ByUserID bool `yaml:"by_user_id"`

	// Custom rate limits by path
	PathLimits map[string]PathRateLimit `yaml:"path_limits"`

	// Rate limit storage backend
	Storage RateLimitStorage `yaml:"-"`
}

// PathRateLimit defines rate limiting for specific paths.
type PathRateLimit struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	BurstSize         int     `yaml:"burst_size"`
}

// CORSConfig configures CORS behavior.
type CORSConfig struct {
	// Enable CORS
	Enabled bool `yaml:"enabled"`

	// Allowed origins
	AllowedOrigins []string `yaml:"allowed_origins"`

	// Allowed methods
	AllowedMethods []string `yaml:"allowed_methods"`

	// Allowed headers
	AllowedHeaders []string `yaml:"allowed_headers"`

	// Exposed headers
	ExposedHeaders []string `yaml:"exposed_headers"`

	// Allow credentials
	AllowCredentials bool `yaml:"allow_credentials"`

	// Max age for preflight requests
	MaxAge time.Duration `yaml:"max_age"`
}

// SecurityHeadersConfig configures security headers.
type SecurityHeadersConfig struct { // nolint: revive
	// Enable security headers
	Enabled bool `yaml:"enabled"`

	// Content Security Policy
	ContentSecurityPolicy string `yaml:"content_security_policy"`

	// X-Frame-Options
	XFrameOptions string `yaml:"x_frame_options"`

	// X-Content-Type-Options
	XContentTypeOptions string `yaml:"x_content_type_options"`

	// X-XSS-Protection
	XXSSProtection string `yaml:"x_xss_protection"`

	// Strict-Transport-Security
	StrictTransportSecurity string `yaml:"strict_transport_security"`

	// Referrer-Policy
	ReferrerPolicy string `yaml:"referrer_policy"`

	// Feature-Policy
	FeaturePolicy string `yaml:"feature_policy"`

	// Permissions-Policy
	PermissionsPolicy string `yaml:"permissions_policy"`
}

// RequestValidationConfig configures request validation.
type RequestValidationConfig struct {
	// Enable request validation
	Enabled bool `yaml:"enabled"`

	// Maximum request body size
	MaxBodySize int64 `yaml:"max_body_size"`

	// Maximum URL length
	MaxURLLength int `yaml:"max_url_length"`

	// Maximum number of headers
	MaxHeaders int `yaml:"max_headers"`

	// Maximum header value length
	MaxHeaderValueLength int `yaml:"max_header_value_length"`

	// Blocked user agents
	BlockedUserAgents []string `yaml:"blocked_user_agents"`

	// Blocked paths
	BlockedPaths []string `yaml:"blocked_paths"`

	// Required headers
	RequiredHeaders []string `yaml:"required_headers"`
}

// IPFilteringConfig configures IP filtering.
type IPFilteringConfig struct {
	// Enable IP filtering
	Enabled bool `yaml:"enabled"`

	// Allowlist of IP addresses/ranges
	AllowList []string `yaml:"allow_list"`

	// Blocklist of IP addresses/ranges
	BlockList []string `yaml:"block_list"`

	// Trusted proxy IPs for X-Forwarded-For
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// RateLimitStorage interface for rate limit storage backends.
type RateLimitStorage interface {
	GetLimiter(key string) *rate.Limiter
	SetLimiter(key string, limiter *rate.Limiter)
	CleanupExpired()
}

// MemoryRateLimitStorage implements in-memory rate limit storage.
type MemoryRateLimitStorage struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// NewMemoryRateLimitStorage creates a new in-memory rate limit storage.
func NewMemoryRateLimitStorage() *MemoryRateLimitStorage {
	storage := &MemoryRateLimitStorage{
		limiters: make(map[string]*rateLimiterEntry),
	}

	// Start cleanup routine
	go storage.cleanupRoutine()

	return storage
}

// GetLimiter retrieves a rate limiter for the given key.
func (m *MemoryRateLimitStorage) GetLimiter(key string) *rate.Limiter {
	m.mu.RLock()
	entry, exists := m.limiters[key]
	m.mu.RUnlock()

	if exists {
		entry.lastUsed = time.Now()
		return entry.limiter
	}

	return nil
}

// SetLimiter sets a rate limiter for the given key.
func (m *MemoryRateLimitStorage) SetLimiter(key string, limiter *rate.Limiter) {
	m.mu.Lock()
	m.limiters[key] = &rateLimiterEntry{
		limiter:  limiter,
		lastUsed: time.Now(),
	}
	m.mu.Unlock()
}

// CleanupExpired removes expired rate limiters.
func (m *MemoryRateLimitStorage) CleanupExpired() {
	cutoff := time.Now().Add(-10 * time.Minute)

	m.mu.Lock()
	for key, entry := range m.limiters {
		if entry.lastUsed.Before(cutoff) {
			delete(m.limiters, key)
		}
	}
	m.mu.Unlock()
}

// cleanupRoutine runs periodic cleanup of expired rate limiters.
func (m *MemoryRateLimitStorage) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.CleanupExpired()
	}
}

// SecurityMiddleware provides comprehensive security middleware.
type SecurityMiddleware struct { // nolint: revive
	config           *SecurityConfig
	rateLimitStorage RateLimitStorage
	allowedIPs       []*net.IPNet
	blockedIPs       []*net.IPNet
	trustedProxies   []*net.IPNet
}

// NewSecurityMiddleware creates a new security middleware instance.
func NewSecurityMiddleware(config *SecurityConfig) (*SecurityMiddleware, error) {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	sm := &SecurityMiddleware{
		config: config,
	}

	// Initialize rate limit storage
	if config.RateLimit != nil && config.RateLimit.Enabled {
		if config.RateLimit.Storage != nil {
			sm.rateLimitStorage = config.RateLimit.Storage
		} else {
			sm.rateLimitStorage = NewMemoryRateLimitStorage()
		}
	}

	// Parse IP filtering configuration
	if config.IPFiltering != nil && config.IPFiltering.Enabled {
		var err error
		sm.allowedIPs, err = parseIPList(config.IPFiltering.AllowList)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP allowlist: %w", err)
		}

		sm.blockedIPs, err = parseIPList(config.IPFiltering.BlockList)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP blocklist: %w", err)
		}

		sm.trustedProxies, err = parseIPList(config.IPFiltering.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trusted proxies: %w", err)
		}
	}

	return sm, nil
}

// parseIPList parses a list of IP addresses and CIDR ranges.
func parseIPList(ipList []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	for _, ipStr := range ipList {
		if ipStr == "" {
			continue
		}

		// Try to parse as CIDR first
		_, network, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try to parse as single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address or CIDR: %s", ipStr)
			}

			// Convert single IP to CIDR
			if ip.To4() != nil {
				_, network, _ = net.ParseCIDR(ipStr + "/32")
			} else {
				_, network, _ = net.ParseCIDR(ipStr + "/128")
			}
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// HTTPMiddleware returns HTTP middleware with security features.
func (sm *SecurityMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := sm.getClientIP(r)

		// IP filtering
		if sm.config.IPFiltering != nil && sm.config.IPFiltering.Enabled {
			if !sm.isIPAllowed(clientIP) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Rate limiting
		if sm.config.RateLimit != nil && sm.config.RateLimit.Enabled {
			if !sm.checkRateLimit(r, clientIP) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		// Request validation
		if sm.config.RequestValidation != nil && sm.config.RequestValidation.Enabled {
			if !sm.validateRequest(r) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
		}

		// CORS handling
		if sm.config.CORS != nil && sm.config.CORS.Enabled {
			if !sm.handleCORS(w, r) {
				return // CORS preflight handled
			}
		}

		// Security headers
		if sm.config.SecurityHeaders != nil && sm.config.SecurityHeaders.Enabled {
			sm.addSecurityHeaders(w)
		}

		next.ServeHTTP(w, r)
	})
}

// GRPCUnaryInterceptor returns a gRPC unary interceptor with security features.
func (sm *SecurityMiddleware) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Get client IP
		clientIP := sm.getClientIPFromContext(ctx)

		// IP filtering
		if sm.config.IPFiltering != nil && sm.config.IPFiltering.Enabled {
			if !sm.isIPAllowed(clientIP) {
				return nil, status.Error(codes.PermissionDenied, "Forbidden")
			}
		}

		// Rate limiting
		if sm.config.RateLimit != nil && sm.config.RateLimit.Enabled {
			if !sm.checkRateLimitGRPC(ctx, info.FullMethod, clientIP) {
				return nil, status.Error(codes.ResourceExhausted, "Too Many Requests")
			}
		}

		// Request validation
		if sm.config.RequestValidation != nil && sm.config.RequestValidation.Enabled {
			if !sm.validateGRPCRequest(ctx, info.FullMethod) {
				return nil, status.Error(codes.InvalidArgument, "Bad Request")
			}
		}

		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor returns a gRPC stream interceptor with security features.
func (sm *SecurityMiddleware) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Get client IP
		clientIP := sm.getClientIPFromContext(stream.Context())

		// IP filtering
		if sm.config.IPFiltering != nil && sm.config.IPFiltering.Enabled {
			if !sm.isIPAllowed(clientIP) {
				return status.Error(codes.PermissionDenied, "Forbidden")
			}
		}

		// Rate limiting
		if sm.config.RateLimit != nil && sm.config.RateLimit.Enabled {
			if !sm.checkRateLimitGRPC(stream.Context(), info.FullMethod, clientIP) {
				return status.Error(codes.ResourceExhausted, "Too Many Requests")
			}
		}

		// Request validation
		if sm.config.RequestValidation != nil && sm.config.RequestValidation.Enabled {
			if !sm.validateGRPCRequest(stream.Context(), info.FullMethod) {
				return status.Error(codes.InvalidArgument, "Bad Request")
			}
		}

		return handler(srv, stream)
	}
}

// getClientIP extracts the client IP from the HTTP request.
func (sm *SecurityMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header from trusted proxies
	if sm.trustedProxies != nil {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Get the proxy IP
			proxyIP := r.RemoteAddr
			if host, _, err := net.SplitHostPort(proxyIP); err == nil {
				proxyIP = host
			}

			// Check if proxy is trusted
			if sm.isIPInList(net.ParseIP(proxyIP), sm.trustedProxies) {
				// Return the first IP from X-Forwarded-For
				ips := strings.Split(xff, ",")
				if len(ips) > 0 {
					return strings.TrimSpace(ips[0])
				}
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// getClientIPFromContext extracts the client IP from the gRPC context.
func (sm *SecurityMiddleware) getClientIPFromContext(ctx context.Context) string {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	host, _, err := net.SplitHostPort(peer.Addr.String())
	if err != nil {
		return peer.Addr.String()
	}

	return host
}

// isIPAllowed checks if an IP is allowed based on allowlist and blocklist.
func (sm *SecurityMiddleware) isIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check blocklist first
	if sm.isIPInList(ip, sm.blockedIPs) {
		return false
	}

	// If allowlist is empty, allow all (except blocked)
	if len(sm.allowedIPs) == 0 {
		return true
	}

	// Check allowlist
	return sm.isIPInList(ip, sm.allowedIPs)
}

// isIPInList checks if an IP is in a list of networks.
func (sm *SecurityMiddleware) isIPInList(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// checkRateLimit checks if the request should be rate limited.
func (sm *SecurityMiddleware) checkRateLimit(r *http.Request, clientIP string) bool {
	// Determine the rate limit key
	key := clientIP
	if sm.config.RateLimit.ByUserID {
		// Extract user ID from context or header
		if userID := r.Header.Get("X-User-ID"); userID != "" {
			key = userID
		}
	}

	// Check for path-specific rate limits
	var pathLimit *PathRateLimit

	for path, limit := range sm.config.RateLimit.PathLimits {
		if strings.HasPrefix(r.URL.Path, path) {
			pathLimit = &limit
			break
		}
	}

	// Get or create rate limiter
	limiter := sm.rateLimitStorage.GetLimiter(key)
	if limiter == nil {
		var rps float64
		var burst int

		if pathLimit != nil {
			rps = pathLimit.RequestsPerSecond
			burst = pathLimit.BurstSize
		} else {
			rps = sm.config.RateLimit.RequestsPerSecond
			burst = sm.config.RateLimit.BurstSize
		}

		limiter = rate.NewLimiter(rate.Limit(rps), burst)
		sm.rateLimitStorage.SetLimiter(key, limiter)
	}

	return limiter.Allow()
}

// checkRateLimitGRPC checks if the gRPC request should be rate limited.
func (sm *SecurityMiddleware) checkRateLimitGRPC(ctx context.Context, method, clientIP string) bool {
	// Similar to HTTP rate limiting but for gRPC
	key := clientIP
	if sm.config.RateLimit.ByUserID {
		// Extract user ID from metadata
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if userIDs := md.Get("user-id"); len(userIDs) > 0 {
				key = userIDs[0]
			}
		}
	}

	// Check for method-specific rate limits
	var pathLimit *PathRateLimit
	for path, limit := range sm.config.RateLimit.PathLimits {
		if strings.HasPrefix(method, path) {
			pathLimit = &limit
			break
		}
	}

	// Get or create rate limiter
	limiter := sm.rateLimitStorage.GetLimiter(key)
	if limiter == nil {
		var rps float64
		var burst int

		if pathLimit != nil {
			rps = pathLimit.RequestsPerSecond
			burst = pathLimit.BurstSize
		} else {
			rps = sm.config.RateLimit.RequestsPerSecond
			burst = sm.config.RateLimit.BurstSize
		}

		limiter = rate.NewLimiter(rate.Limit(rps), burst)
		sm.rateLimitStorage.SetLimiter(key, limiter)
	}

	return limiter.Allow()
}

// validateRequest validates the HTTP request.
func (sm *SecurityMiddleware) validateRequest(r *http.Request) bool {
	config := sm.config.RequestValidation

	// Check request body size
	if config.MaxBodySize > 0 && r.ContentLength > config.MaxBodySize {
		return false
	}

	// Check URL length
	if config.MaxURLLength > 0 && len(r.URL.String()) > config.MaxURLLength {
		return false
	}

	// Check number of headers
	if config.MaxHeaders > 0 && len(r.Header) > config.MaxHeaders {
		return false
	}

	// Check header value lengths
	if config.MaxHeaderValueLength > 0 {
		for _, values := range r.Header {
			for _, value := range values {
				if len(value) > config.MaxHeaderValueLength {
					return false
				}
			}
		}
	}

	// Check blocked user agents
	if len(config.BlockedUserAgents) > 0 {
		userAgent := r.Header.Get("User-Agent")
		for _, blocked := range config.BlockedUserAgents {
			if strings.Contains(userAgent, blocked) {
				return false
			}
		}
	}

	// Check blocked paths
	if len(config.BlockedPaths) > 0 {
		for _, blocked := range config.BlockedPaths {
			if strings.HasPrefix(r.URL.Path, blocked) {
				return false
			}
		}
	}

	// Check required headers
	if len(config.RequiredHeaders) > 0 {
		for _, required := range config.RequiredHeaders {
			if r.Header.Get(required) == "" {
				return false
			}
		}
	}

	return true
}

// validateGRPCRequest validates the gRPC request.
func (sm *SecurityMiddleware) validateGRPCRequest(ctx context.Context, method string) bool {
	config := sm.config.RequestValidation

	// Check blocked paths
	if len(config.BlockedPaths) > 0 {
		for _, blocked := range config.BlockedPaths {
			if strings.HasPrefix(method, blocked) {
				return false
			}
		}
	}

	// Check required headers (metadata)
	if len(config.RequiredHeaders) > 0 {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return false
		}

		for _, required := range config.RequiredHeaders {
			if len(md.Get(required)) == 0 {
				return false
			}
		}
	}

	return true
}

// handleCORS handles CORS requests.
func (sm *SecurityMiddleware) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	config := sm.config.CORS

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Not a CORS request
	}

	// Check if origin is allowed
	if !sm.isOriginAllowed(origin) {
		return true // Origin not allowed, continue without CORS headers
	}

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if len(config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}

	// Handle preflight request
	if r.Method == "OPTIONS" {
		if len(config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		}

		if len(config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		}

		if config.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(int(config.MaxAge.Seconds())))
		}

		w.WriteHeader(http.StatusNoContent)
		return false // Preflight handled
	}

	return true
}

// isOriginAllowed checks if an origin is allowed.
func (sm *SecurityMiddleware) isOriginAllowed(origin string) bool {
	config := sm.config.CORS

	if len(config.AllowedOrigins) == 0 {
		return false
	}

	for _, allowed := range config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}

		// Simple wildcard matching
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}
	}

	return false
}

// addSecurityHeaders adds security headers to the response.
func (sm *SecurityMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	config := sm.config.SecurityHeaders

	if config.ContentSecurityPolicy != "" {
		w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
	}

	if config.XFrameOptions != "" {
		w.Header().Set("X-Frame-Options", config.XFrameOptions)
	}

	if config.XContentTypeOptions != "" {
		w.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
	}

	if config.XXSSProtection != "" {
		w.Header().Set("X-XSS-Protection", config.XXSSProtection)
	}

	if config.StrictTransportSecurity != "" {
		w.Header().Set("Strict-Transport-Security", config.StrictTransportSecurity)
	}

	if config.ReferrerPolicy != "" {
		w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
	}

	if config.FeaturePolicy != "" {
		w.Header().Set("Feature-Policy", config.FeaturePolicy)
	}

	if config.PermissionsPolicy != "" {
		w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
	}
}

// DefaultSecurityConfig returns a default security configuration.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         200,
			ByUserID:          false,
			PathLimits:        make(map[string]PathRateLimit),
		},
		CORS: &CORSConfig{
			Enabled:          true,
			AllowedOrigins:   []string{"http://localhost:3000"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
			ExposedHeaders:   []string{"X-Total-Count"},
			AllowCredentials: true,
			MaxAge:           24 * time.Hour,
		},
		SecurityHeaders: &SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "default-src 'self'",
			XFrameOptions:           "DENY",
			XContentTypeOptions:     "nosniff",
			XXSSProtection:          "1; mode=block",
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
			ReferrerPolicy:          "strict-origin-when-cross-origin",
			FeaturePolicy:           "geolocation 'none'; microphone 'none'; camera 'none'",
			PermissionsPolicy:       "geolocation=(), microphone=(), camera=()",
		},
		RequestValidation: &RequestValidationConfig{
			Enabled:              true,
			MaxBodySize:          10 * 1024 * 1024, // 10MB
			MaxURLLength:         2048,
			MaxHeaders:           100,
			MaxHeaderValueLength: 8192,
			BlockedUserAgents:    []string{"bot", "crawler", "spider"},
			BlockedPaths:         []string{},
			RequiredHeaders:      []string{},
		},
		IPFiltering: &IPFilteringConfig{
			Enabled:        false,
			AllowList:      []string{},
			BlockList:      []string{},
			TrustedProxies: []string{"127.0.0.1", "::1"},
		},
	}
}
