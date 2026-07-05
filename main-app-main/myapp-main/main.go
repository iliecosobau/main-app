package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var pageTemplate = template.Must(template.ParseFiles("main.html"))

type Note struct {
	Title   string
	Content string
}

type PageData struct {
	Message string
	Notes   []Note
}

var users = map[string]Login{}
var sessions = map[string]string{}
var db *sql.DB

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
	})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		sessionCookie, err := r.Cookie("session_token")
		if err != nil {
			clearAuthCookies(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if sessions[sessionCookie.Value] == "" {
			delete(sessions, sessionCookie.Value)
			clearAuthCookies(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func main() {

	connStr := "postgres://postgres:secret@localhost:5432/gopgtest?sslmode=disable"

	var err error

	db, err = sql.Open("postgres", connStr)

	defer db.Close()

	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	CreateTable(db)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/main", requireAuth(mainPage))

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/notes", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		notesHandler(w, r, db)
	}))

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

	_, err := db.Exec(`
    INSERT INTO users (username, password_hash)
    VALUES ($1, $2)
`, username, hashedPassword)
	if err != nil {
		http.Error(w, "could not save user", http.StatusInternalServerError)
		return
	}

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

	row := db.QueryRow(`
    SELECT password_hash
    FROM users
    WHERE username = $1
`, username)

	var storedHash string
	if err := row.Scan(&storedHash); err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	if !checkPasswordHash(password, storedHash) {
		er := http.StatusUnauthorized
		http.Error(w, "invalid username or pasword", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)
	sessions[sessionToken] = username

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Path:     "/",
	})

	http.Redirect(w, r, "/main", http.StatusSeeOther)
}
func logout(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		delete(sessions, sessionCookie.Value)
	}

	clearAuthCookies(w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func protected(w http.ResponseWriter, r *http.Request) {}

func CreateTable(db *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);`

	query2 := `CREATE TABLE IF NOT EXISTS notes (
	id SERIAL PRIMARY KEY,
	userid INTEGER NOT NULL REFERENCES users(id),
	title TEXT,
	content TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(query2)
	if err != nil {
		log.Fatal(err)
	}
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := sessions[sessionCookie.Value]

	notes, err := fetchUserNotes(username)
	if err != nil {
		http.Error(w, "could not load notes", http.StatusInternalServerError)
		return
	}

	pageTemplate.Execute(w, PageData{Notes: notes})
}

func fetchUserNotes(username string) ([]Note, error) {
	rows, err := db.Query(`SELECT title, content
	FROM notes
	WHERE userid = (SELECT id FROM users WHERE username = $1)
	ORDER BY created_at DESC`, username)

	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []Note
	for rows.Next() {
		var note Note
		if err := rows.Scan(&note.Title, &note.Content); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}
	return notes, rows.Err()
}

func notesHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}

	username := sessions[sessionCookie.Value]

	notes := r.FormValue("notes")
	title := r.FormValue("title")

	if notes == "" || title == "" {
		http.Error(w, "Notes and title cannot be empty", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(`
    INSERT INTO notes (userid, title, content)
    VALUES ((SELECT id FROM users WHERE username = $1), $2, $3)
	`, username, title, notes)

	if err != nil {

		http.Error(w, "could not save note", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Notes saved successfully!")

}
