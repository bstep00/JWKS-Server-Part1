package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

// Key holds an RSA key pair
type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	Expiry     time.Time
}

// keys stores all the RSA keys
var keys []Key

// generateKey creates a new RSA key pair and adds it to keys
func generateKey(expired bool) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	expiry := time.Now().Add(24 * time.Hour)
	if expired {
		expiry = time.Now().Add(-1 * time.Hour)
	}
	keys = append(keys, Key{
		ID:         fmt.Sprintf("key%d", len(keys)+1),
		PrivateKey: privateKey,
		Expiry:     expiry,
	})
}

// jwksHandler sends the public keys as a JWKS
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	// Add non-expired keys to the JWKS
	for _, key := range keys {
		if key.Expiry.After(time.Now()) {
			jwks.Keys = append(jwks.Keys, map[string]string{
				"kid": key.ID,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PrivateKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PrivateKey.E)).Bytes()),
			})
		}
	}

	json.NewEncoder(w).Encode(jwks)
}

// authHandler creates and sends a JWT
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wantExpired := r.URL.Query().Get("expired") == "true"
	var key Key
	for _, k := range keys {
		if (wantExpired && k.Expiry.Before(time.Now())) || (!wantExpired && k.Expiry.After(time.Now())) {
			key = k
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

	tokenString, _ := token.SignedString(key.PrivateKey)
	w.Write([]byte(tokenString))
}

func main() {
	generateKey(false) // Valid key
	generateKey(true)  // Expired key

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("Server starting...")
	http.ListenAndServe(":8080", nil)
}
