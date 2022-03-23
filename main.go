package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

// TODO: 本番では固定値ではなく、ブラウザごとに異なる値を生成して保存してください
// https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12
// The binding value used for CSRF
// protection MUST contain a non-guessable value (as described in Section 10.10),
// and the user-agent's authenticated state (e.g., session cookie, HTML5 local storage) MUST be kept in a location
// accessible only to the client and the user-agent (i.e., protected by same-origin policy)
const state = "FIXME"

var (
	config = oauth2.Config{
		ClientID:     os.Getenv("TWITTER_CLIENT_ID"),
		ClientSecret: os.Getenv("TWITTER_CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://twitter.com/i/oauth2/authorize",
			TokenURL:  "https://api.twitter.com/2/oauth2/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"tweet.read", "users.read", "tweet.write"},
	}

	codeVerifier string
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/callback", callbackHandler).Methods("GET")

	srv := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:8080",
	}

	log.Println("Click the following link to login: http://localhost:8080/login")
	log.Fatal(srv.ListenAndServe())
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := buildAuthorizationURL(config)
	log.Println(url)
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusFound)
	return
}

func buildAuthorizationURL(config oauth2.Config) string {

	// PKCE 対応 https://datatracker.ietf.org/doc/html/rfc7636
	// TODO: 本番ではブラウザごとのセッションに保存してください
	codeVerifier = generateBase64Encoded32byteRandomString()
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashed := h.Sum(nil)
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)

	url := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	return url
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	queryCode := r.URL.Query().Get("code")
	if queryCode == "" {
		log.Println("code not found")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	queryState := r.URL.Query().Get("state")
	if queryState == "" {
		log.Println("state not found")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if queryState != state {
		log.Println("invalid state")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := config.Exchange(context.Background(), queryCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Printf("failed to exchange token: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	log.Printf("token scope: %v\n", token.Extra("scope"))

	oAuthClient := oauth2.NewClient(r.Context(), oauth2.StaticTokenSource(token))

	// https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
	res, err := oAuthClient.Get("https://api.twitter.com/2/users/me")
	if err != nil {
		log.Printf("failed to get me: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, res.Body)
}

func generateBase64Encoded32byteRandomString() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
