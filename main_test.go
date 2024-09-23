package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerateKey(t *testing.T) {
	initialKeyCount := len(keys)
	generateKey(false)
	if len(keys) != initialKeyCount+1 {
		t.Errorf("generateKey failed to add a new key")
	}
	if keys[len(keys)-1].Expiry.Before(time.Now()) {
		t.Errorf("generateKey(false) created an expired key")
	}

	generateKey(true)
	if len(keys) != initialKeyCount+2 {
		t.Errorf("generateKey failed to add a new key")
	}
	if keys[len(keys)-1].Expiry.After(time.Now()) {
		t.Errorf("generateKey(true) did not create an expired key")
	}
}

func TestJWKSHandler(t *testing.T) {
	// Test GET method
	req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(jwksHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	err = json.Unmarshal(rr.Body.Bytes(), &jwks)
	if err != nil {
		t.Errorf("Failed to parse JWKS response: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Errorf("JWKS response contained no keys")
	}

	// Test wrong HTTP method
	req, _ = http.NewRequest("POST", "/.well-known/jwks.json", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code for POST: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestAuthHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		queryParam     string
		expectedStatus int
	}{
		{"Valid JWT", "POST", "", http.StatusCreated},
		{"Expired JWT", "POST", "?expired=true", http.StatusCreated},
		{"Wrong Method", "GET", "", http.StatusMethodNotAllowed},
		{"No Suitable Key", "POST", "?expired=invalid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/auth"+tt.queryParam, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(authHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusCreated {
				if len(rr.Body.String()) == 0 {
					t.Errorf("Expected a JWT, got an empty response")
				}
			}
		})
	}
}

func TestMain(t *testing.T) {
	// This test just ensures that the main function doesn't panic
	go func() {
		main()
	}()
	// Wait a bit for the server to start
	time.Sleep(100 * time.Millisecond)
}
