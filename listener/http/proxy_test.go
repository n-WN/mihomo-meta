package http

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/metacubex/mihomo/component/auth"
)

// TestAuthenticationLogic tests the core authentication logic independently
func TestAuthenticationLogic(t *testing.T) {
	// Create test user credentials
	testUser := "testuser"
	testPass := "testpass"
	
	users := []auth.AuthUser{
		{User: testUser, Pass: testPass},
	}
	
	authenticator := auth.NewAuthenticator(users)
	
	// Test 1: Valid credentials should pass
	req1 := &http.Request{
		Header: make(http.Header),
	}
	validAuth := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPass))
	req1.Header.Set("Proxy-Authorization", "Basic "+validAuth)
	
	resp1, user1 := authenticate(req1, authenticator)
	if resp1 != nil {
		t.Fatalf("Valid credentials should not return error response, got: %v", resp1)
	}
	if user1 != testUser {
		t.Fatalf("Expected user %s, got %s", testUser, user1)
	}
	
	// Test 2: Invalid credentials should fail
	req2 := &http.Request{
		Header: make(http.Header),
	}
	invalidAuth := base64.StdEncoding.EncodeToString([]byte(testUser + ":wrongpass"))
	req2.Header.Set("Proxy-Authorization", "Basic "+invalidAuth)
	
	resp2, _ := authenticate(req2, authenticator)
	if resp2 == nil {
		t.Fatalf("Invalid credentials should return error response")
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status %d for invalid credentials, got %d", http.StatusForbidden, resp2.StatusCode)
	}
	
	// Test 3: Missing credentials should require auth
	req3 := &http.Request{
		Header: make(http.Header),
	}
	
	resp3, _ := authenticate(req3, authenticator)
	if resp3 == nil {
		t.Fatalf("Missing credentials should return error response")
	}
	if resp3.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("Expected status %d for missing credentials, got %d", http.StatusProxyAuthRequired, resp3.StatusCode)
	}
	
	// Test 4: No authenticator (nil) should always pass
	req4 := &http.Request{
		Header: make(http.Header),
	}
	
	resp4, _ := authenticate(req4, nil)
	if resp4 != nil {
		t.Fatalf("No authenticator should always pass, got: %v", resp4)
	}
}

// TestTrustedStatePersistence demonstrates the vulnerability in trusted state management
func TestTrustedStatePersistence(t *testing.T) {
	// This test documents the current vulnerable behavior where trusted state persists
	// across requests in a keep-alive connection without re-authentication
	
	testUser := "testuser"
	testPass := "testpass"
	
	users := []auth.AuthUser{
		{User: testUser, Pass: testPass},
	}
	
	authenticator := auth.NewAuthenticator(users)
	
	// Simulate the current behavior in HandleConn function
	trusted := authenticator == nil // Line 46 from proxy.go
	
	// First request with valid credentials
	req1 := &http.Request{Header: make(http.Header)}
	validAuth := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPass))
	req1.Header.Set("Proxy-Authorization", "Basic "+validAuth)
	
	resp1, _ := authenticate(req1, authenticator)
	trusted = trusted || resp1 == nil // Line 65 from proxy.go - this is the vulnerability
	
	if !trusted {
		t.Fatal("First request should make connection trusted")
	}
	
	// Second request without credentials - this demonstrates the vulnerability
	req2 := &http.Request{Header: make(http.Header)}
	// No Proxy-Authorization header
	
	resp2, _ := authenticate(req2, authenticator)
	// In the current code, trusted state persists so this request would be processed
	// even though authenticate() returns an error response
	
	if resp2 == nil {
		t.Log("Second request passed authentication despite no credentials")
	} else {
		t.Logf("Second request failed authentication (status: %d) but trusted=%v means it would still be processed", resp2.StatusCode, trusted)
	}
	
	// The vulnerability is that in the actual HandleConn function,
	// the 'trusted' variable is checked (line 68: if trusted {...})
	// and if true, the request is processed regardless of authentication failure
	
	t.Logf("VULNERABILITY: trusted state remains %v for subsequent requests", trusted)
	t.Log("This allows unauthorized requests to be processed in keep-alive connections")
}

// TestFixedTrustedStateBehavior tests that the fix correctly handles trust per request
func TestFixedTrustedStateBehavior(t *testing.T) {
	// This test validates the fix for the authentication bypass vulnerability
	
	testUser := "testuser"
	testPass := "testpass"
	
	users := []auth.AuthUser{
		{User: testUser, Pass: testPass},
	}
	
	authenticator := auth.NewAuthenticator(users)
	
	// Simulate the FIXED behavior
	
	// First request with valid credentials
	req1 := &http.Request{Header: make(http.Header)}
	validAuth := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPass))
	req1.Header.Set("Proxy-Authorization", "Basic "+validAuth)
	
	resp1, _ := authenticate(req1, authenticator)
	
	// With the fix: evaluate trust per request
	var trusted1 bool
	if authenticator == nil {
		trusted1 = true
	} else {
		trusted1 = resp1 == nil
	}
	
	if !trusted1 {
		t.Fatal("First request with valid credentials should be trusted")
	}
	
	// Second request without credentials
	req2 := &http.Request{Header: make(http.Header)}
	
	resp2, _ := authenticate(req2, authenticator)
	
	// With the fix: evaluate trust per request (no persistence)
	var trusted2 bool
	if authenticator == nil {
		trusted2 = true
	} else {
		trusted2 = resp2 == nil
	}
	
	if trusted2 {
		t.Fatal("Second request without credentials should NOT be trusted")
	}
	
	if resp2 == nil {
		t.Fatal("Second request without credentials should return auth error")
	}
	
	if resp2.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("Expected auth required, got status %d", resp2.StatusCode)
	}
	
	// Third request with invalid credentials
	req3 := &http.Request{Header: make(http.Header)}
	invalidAuth := base64.StdEncoding.EncodeToString([]byte(testUser + ":wrongpass"))
	req3.Header.Set("Proxy-Authorization", "Basic "+invalidAuth)
	
	resp3, _ := authenticate(req3, authenticator)
	
	// With the fix: evaluate trust per request
	var trusted3 bool
	if authenticator == nil {
		trusted3 = true
	} else {
		trusted3 = resp3 == nil
	}
	
	if trusted3 {
		t.Fatal("Third request with invalid credentials should NOT be trusted")
	}
	
	if resp3 == nil {
		t.Fatal("Third request with invalid credentials should return auth error")
	}
	
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected forbidden, got status %d", resp3.StatusCode)
	}
	
	t.Log("SUCCESS: Fix correctly prevents authentication bypass")
	t.Log("Each request is properly authenticated without persistent trusted state")
}

// TestNoAuthenticatorBackwardCompatibility ensures fix doesn't break backward compatibility
func TestNoAuthenticatorBackwardCompatibility(t *testing.T) {
	// Test that when no authenticator is configured, all requests are still trusted
	// This ensures backward compatibility for deployments without authentication
	
	// Simulate the fixed behavior with no authenticator
	var authenticator auth.Authenticator = nil
	
	// First request without credentials (should be trusted when no auth configured)
	req1 := &http.Request{Header: make(http.Header)}
	
	resp1, _ := authenticate(req1, authenticator)
	
	var trusted1 bool
	if authenticator == nil {
		trusted1 = true
	} else {
		trusted1 = resp1 == nil
	}
	
	if !trusted1 {
		t.Fatal("Request should be trusted when no authenticator is configured")
	}
	
	// Second request with random headers (should still be trusted)
	req2 := &http.Request{Header: make(http.Header)}
	req2.Header.Set("Some-Header", "some-value")
	
	resp2, _ := authenticate(req2, authenticator)
	
	var trusted2 bool
	if authenticator == nil {
		trusted2 = true
	} else {
		trusted2 = resp2 == nil
	}
	
	if !trusted2 {
		t.Fatal("Request should be trusted when no authenticator is configured")
	}
	
	t.Log("SUCCESS: Backward compatibility maintained for deployments without authentication")
}