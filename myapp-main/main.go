package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessioToken    string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)

	// Start the server
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "invalid method", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(w, "invalid username/password", er)
		return
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "User Already Exists", er)
		return
	}

	hashedPassword, _ := hashpasswords(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}
	fmt.Fprintln(w, "User Registered successfully!")
}
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Request Method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]

	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "invalid username or pasword", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	user.SessioToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login Succes")
}
func logout(w http.ResponseWriter, r *http.Request)    {}
func protected(w http.ResponseWriter, r *http.Request) {}
