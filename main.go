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

// Key holds an RSA key pair and its metadata
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
	keyFound := false
	for i := len(keys) - 1; i >= 0; i-- {
		if (wantExpired && keys[i].Expiry.Before(time.Now())) || (!wantExpired && keys[i].Expiry.After(time.Now())) {
			key = keys[i]
			keyFound = true
			break
		}
	}

	if !keyFound {
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
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(tokenString))
}

func main() {
	generateKey(false) // Valid key
	generateKey(true)  // Expired key

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("Starting server...")
	http.ListenAndServe(":8080", nil)
}
