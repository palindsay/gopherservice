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

package security

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()
	require.NotNil(t, config)

	assert.True(t, config.RateLimit.Enabled)
	assert.Equal(t, 100.0, config.RateLimit.RequestsPerSecond)
	assert.Equal(t, 200, config.RateLimit.BurstSize)

	assert.True(t, config.CORS.Enabled)
	assert.Contains(t, config.CORS.AllowedOrigins, "http://localhost:3000")

	assert.True(t, config.SecurityHeaders.Enabled)
	assert.Equal(t, "DENY", config.SecurityHeaders.XFrameOptions)

	assert.True(t, config.RequestValidation.Enabled)
	assert.Equal(t, int64(10*1024*1024), config.RequestValidation.MaxBodySize)

	assert.False(t, config.IPFiltering.Enabled)
}

func TestNewSecurityMiddleware(t *testing.T) {
	config := DefaultSecurityConfig()

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)
	require.NotNil(t, sm)

	assert.Equal(t, config, sm.config)
	assert.NotNil(t, sm.rateLimitStorage)
}

func TestNewSecurityMiddlewareWithNilConfig(t *testing.T) {
	sm, err := NewSecurityMiddleware(nil)
	require.NoError(t, err)
	require.NotNil(t, sm)

	assert.NotNil(t, sm.config)
}

func TestParseIPList(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected int
		hasError bool
	}{
		{
			name:     "Valid CIDR",
			input:    []string{"192.168.1.0/24", "10.0.0.0/8"},
			expected: 2,
			hasError: false,
		},
		{
			name:     "Valid IP",
			input:    []string{"192.168.1.1", "10.0.0.1"},
			expected: 2,
			hasError: false,
		},
		{
			name:     "Mixed",
			input:    []string{"192.168.1.0/24", "10.0.0.1"},
			expected: 2,
			hasError: false,
		},
		{
			name:     "Invalid IP",
			input:    []string{"invalid-ip"},
			expected: 0,
			hasError: true,
		},
		{
			name:     "Empty strings",
			input:    []string{"", "192.168.1.0/24", ""},
			expected: 1,
			hasError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			networks, err := parseIPList(tc.input)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, networks, tc.expected)
			}
		})
	}
}

func TestMemoryRateLimitStorage(t *testing.T) {
	storage := NewMemoryRateLimitStorage()
	require.NotNil(t, storage)

	key := "test-key"

	// Test GetLimiter with non-existent key
	limiter := storage.GetLimiter(key)
	assert.Nil(t, limiter)

	// Test SetLimiter and GetLimiter
	testLimiter := rate.NewLimiter(rate.Limit(10), 20)
	storage.SetLimiter(key, testLimiter)

	retrievedLimiter := storage.GetLimiter(key)
	assert.Equal(t, testLimiter, retrievedLimiter)

	// Test CleanupExpired
	storage.CleanupExpired()

	// Should still exist as it was just accessed
	retrievedLimiter = storage.GetLimiter(key)
	assert.Equal(t, testLimiter, retrievedLimiter)
}

func TestHTTPMiddleware(t *testing.T) {
	config := DefaultSecurityConfig()
	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middleware := sm.HTTPMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "OK")

	// Check security headers
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}

func TestHTTPMiddlewareRateLimit(t *testing.T) {
	config := DefaultSecurityConfig()
	config.RateLimit.RequestsPerSecond = 1
	config.RateLimit.BurstSize = 1

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := sm.HTTPMiddleware(handler)

	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Second request should be rate limited
	req = httptest.NewRequest("GET", "/test", nil)
	rec = httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestHTTPMiddlewareIPFiltering(t *testing.T) {
	config := DefaultSecurityConfig()
	config.IPFiltering.Enabled = true
	config.IPFiltering.BlockList = []string{"192.168.1.1"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := sm.HTTPMiddleware(handler)

	// Test with blocked IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Test with allowed IP
	req = httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	rec = httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareRequestValidation(t *testing.T) {
	config := DefaultSecurityConfig()
	config.RequestValidation.MaxURLLength = 10
	config.RequestValidation.BlockedUserAgents = []string{"bad-bot"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := sm.HTTPMiddleware(handler)

	// Test URL length validation
	req := httptest.NewRequest("GET", "/very-long-url-that-exceeds-limit", nil)
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test blocked user agent
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "bad-bot/1.0")
	rec = httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test valid request
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "good-bot/1.0")
	rec = httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareCORS(t *testing.T) {
	config := DefaultSecurityConfig()
	config.CORS.AllowedOrigins = []string{"http://example.com"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := sm.HTTPMiddleware(handler)

	// Test CORS preflight
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))

	// Test actual request with CORS
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	rec = httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestGetClientIP(t *testing.T) {
	config := DefaultSecurityConfig()
	config.IPFiltering.Enabled = true
	config.IPFiltering.TrustedProxies = []string{"127.0.0.1"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expected      string
	}{
		{
			name:       "Direct connection",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "127.0.0.1:12345",
			xRealIP:    "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For from trusted proxy",
			remoteAddr:    "127.0.0.1:12345",
			xForwardedFor: "192.168.1.1, 10.0.0.1",
			expected:      "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For from untrusted proxy",
			remoteAddr:    "192.168.1.100:12345",
			xForwardedFor: "192.168.1.1, 10.0.0.1",
			expected:      "192.168.1.100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.remoteAddr

			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}

			clientIP := sm.getClientIP(req)
			assert.Equal(t, tc.expected, clientIP)
		})
	}
}

func TestGRPCUnaryInterceptor(t *testing.T) {
	config := DefaultSecurityConfig()
	config.RateLimit.RequestsPerSecond = 1
	config.RateLimit.BurstSize = 1

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	interceptor := sm.GRPCUnaryInterceptor()

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "OK", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Create context with peer info
	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 12345,
		},
	}
	ctx := peer.NewContext(context.Background(), p)

	// First request should succeed
	resp, err := interceptor(ctx, nil, info, handler)
	assert.NoError(t, err)
	assert.Equal(t, "OK", resp)

	// Second request should be rate limited
	_, err = interceptor(ctx, nil, info, handler)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Too Many Requests")
}

func TestGRPCStreamInterceptor(t *testing.T) {
	config := DefaultSecurityConfig()
	config.IPFiltering.Enabled = true
	config.IPFiltering.BlockList = []string{"192.168.1.1"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	interceptor := sm.GRPCStreamInterceptor()

	handler := func(_ interface{}, _ grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Create context with blocked IP
	p := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
	}
	ctx := peer.NewContext(context.Background(), p)

	// Create mock stream
	stream := &mockServerStream{ctx: ctx}

	err = interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestIsIPAllowed(t *testing.T) {
	config := DefaultSecurityConfig()
	config.IPFiltering.Enabled = true
	config.IPFiltering.AllowList = []string{"192.168.1.0/24"}
	config.IPFiltering.BlockList = []string{"192.168.1.100"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	// Test allowed IP
	assert.True(t, sm.isIPAllowed("192.168.1.1"))

	// Test blocked IP (should override allowlist)
	assert.False(t, sm.isIPAllowed("192.168.1.100"))

	// Test disallowed IP
	assert.False(t, sm.isIPAllowed("10.0.0.1"))

	// Test invalid IP
	assert.False(t, sm.isIPAllowed("invalid-ip"))
}

func TestIsOriginAllowed(t *testing.T) {
	config := DefaultSecurityConfig()
	config.CORS.AllowedOrigins = []string{"http://example.com", "*.example.org"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	testCases := []struct {
		origin   string
		expected bool
	}{
		{"http://example.com", true},
		{"http://subdomain.example.org", true},
		{"http://example.org", true},
		{"http://other.com", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.origin, func(t *testing.T) {
			result := sm.isOriginAllowed(tc.origin)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateRequest(t *testing.T) {
	config := DefaultSecurityConfig()
	config.RequestValidation.MaxBodySize = 100
	config.RequestValidation.MaxURLLength = 20
	config.RequestValidation.MaxHeaders = 2
	config.RequestValidation.MaxHeaderValueLength = 10
	config.RequestValidation.BlockedUserAgents = []string{"bad"}
	config.RequestValidation.BlockedPaths = []string{"/admin"}
	config.RequestValidation.RequiredHeaders = []string{"X-API-Key"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		method   string
		url      string
		headers  map[string]string
		bodySize int64
		expected bool
	}{
		{
			name:     "Valid request",
			method:   "GET",
			url:      "/test",
			headers:  map[string]string{"X-API-Key": "test"},
			bodySize: 50,
			expected: true,
		},
		{
			name:     "Body too large",
			method:   "POST",
			url:      "/test",
			headers:  map[string]string{"X-API-Key": "test"},
			bodySize: 200,
			expected: false,
		},
		{
			name:     "URL too long",
			method:   "GET",
			url:      "/very-long-url-that-exceeds-limit",
			headers:  map[string]string{"X-API-Key": "test"},
			bodySize: 50,
			expected: false,
		},
		{
			name:     "Blocked user agent",
			method:   "GET",
			url:      "/test",
			headers:  map[string]string{"X-API-Key": "test", "User-Agent": "bad-bot"},
			bodySize: 50,
			expected: false,
		},
		{
			name:     "Blocked path",
			method:   "GET",
			url:      "/admin/users",
			headers:  map[string]string{"X-API-Key": "test"},
			bodySize: 50,
			expected: false,
		},
		{
			name:     "Missing required header",
			method:   "GET",
			url:      "/test",
			headers:  map[string]string{},
			bodySize: 50,
			expected: false,
		},
		{
			name:     "Header value too long",
			method:   "GET",
			url:      "/test",
			headers:  map[string]string{"X-API-Key": "very-long-value"},
			bodySize: 50,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(""))
			req.ContentLength = tc.bodySize

			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			result := sm.validateRequest(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateGRPCRequest(t *testing.T) {
	config := DefaultSecurityConfig()
	config.RequestValidation.BlockedPaths = []string{"/admin"}
	config.RequestValidation.RequiredHeaders = []string{"api-key"}

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		method   string
		metadata map[string]string
		expected bool
	}{
		{
			name:     "Valid request",
			method:   "/test.Service/Method",
			metadata: map[string]string{"api-key": "test"},
			expected: true,
		},
		{
			name:     "Blocked path",
			method:   "/admin.Service/Method",
			metadata: map[string]string{"api-key": "test"},
			expected: false,
		},
		{
			name:     "Missing required header",
			method:   "/test.Service/Method",
			metadata: map[string]string{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			md := metadata.New(tc.metadata)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			result := sm.validateGRPCRequest(ctx, tc.method)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestAddSecurityHeaders(t *testing.T) {
	config := DefaultSecurityConfig()
	config.SecurityHeaders.ContentSecurityPolicy = "default-src 'self'"
	config.SecurityHeaders.XFrameOptions = "DENY"

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	sm.addSecurityHeaders(rec)

	assert.Equal(t, "default-src 'self'", rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}

// mockServerStream is a mock implementation of grpc.ServerStream for testing.
type mockServerStream struct {
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(_ interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(_ interface{}) error {
	return nil
}

func (m *mockServerStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(metadata.MD) {}

func TestSecurityMiddlewareWithCustomStorage(t *testing.T) {
	config := DefaultSecurityConfig()
	customStorage := NewMemoryRateLimitStorage()
	config.RateLimit.Storage = customStorage

	sm, err := NewSecurityMiddleware(config)
	require.NoError(t, err)

	assert.Equal(t, customStorage, sm.rateLimitStorage)
}

func TestSecurityMiddlewareIPFilteringError(t *testing.T) {
	config := DefaultSecurityConfig()
	config.IPFiltering.Enabled = true
	config.IPFiltering.AllowList = []string{"invalid-ip"}

	_, err := NewSecurityMiddleware(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse IP allowlist")
}
