// Package main implements a basic JWKS server with JWT issuance capabilities.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

// Key represents a RSA key pair with metadata
type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	Expiry     time.Time
}

var keys []Key

// generateKey creates a new RSA key pair and adds it to the keys slice
func generateKey(expired bool) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	expiry := time.Now().Add(24 * time.Hour)
	if expired {
		expiry = time.Now().Add(-1 * time.Hour)
	}
	keys = append(keys, Key{
		ID:         strconv.Itoa(len(keys) + 1),
		PrivateKey: privateKey,
		Expiry:     expiry,
	})
}

// jwksHandler serves the JWKS (JSON Web Key Set) containing public keys
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type jwk struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	var jwks struct {
		Keys []jwk `json:"keys"`
	}

	// Add non-expired keys to the JWKS
	for _, key := range keys {
		if key.Expiry.After(time.Now()) {
			jwks.Keys = append(jwks.Keys, jwk{
				Kid: key.ID,
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.PrivateKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PrivateKey.E)).Bytes()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("Error encoding JWKS: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// authHandler issues JWTs based on the request parameters
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wantExpired := r.URL.Query().Get("expired") == "true"
	var key Key
	for i := len(keys) - 1; i >= 0; i-- {
		if (wantExpired && keys[i].Expiry.Before(time.Now())) || (!wantExpired && keys[i].Expiry.After(time.Now())) {
			key = keys[i]
			break
		}
	}

	if key.PrivateKey == nil {
		http.Error(w, "No suitable key found", http.StatusNotFound)
		return
	}

	// Create and sign the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": key.Expiry.Unix(),
	})
	token.Header["kid"] = key.ID

	tokenString, err := token.SignedString(key.PrivateKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write([]byte(tokenString)); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func main() {
	// Generate initial keys (one valid, one expired)
	generateKey(false) // Valid key
	generateKey(true)  // Expired key

	// Set up HTTP handlers
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	// Start the server
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}