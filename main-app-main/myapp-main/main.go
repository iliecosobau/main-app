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

type migration struct {
	name string
	sql  string
}

type App struct {
	authService *AuthService
	noteService *NoteService
}

type AuthService struct {
	userRepo *UserRepository
	sessions map[string]string
}

type UserRepository struct {
	db *sql.DB
}

type NotesHandler struct {
	username string
}

type NoteService struct {
	noteRepo *NoteRepository
}

type NoteRepository struct {
	db *sql.DB
}

func NewNoteRepository(db *sql.DB) *NoteRepository {
	return &NoteRepository{db: db}
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

func requireAuth(next http.HandlerFunc, app *App) http.HandlerFunc {
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

		if _, ok := app.authService.sessions[sessionCookie.Value]; !ok {
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
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	if err := applyMigrations(db); err != nil {
		log.Fatal(err)
	}

	userRepo := &UserRepository{db: db}
	authService := &AuthService{
		userRepo: userRepo,
		sessions: map[string]string{},
	}

	noteRepo := &NoteRepository{db: db}
	noteService := &NoteService{noteRepo: noteRepo}

	app := &App{
		authService: authService,
		noteService: noteService,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/main", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		mainPage(w, r, app)
	}, app))

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		register(w, r, app)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, app)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		logout(w, r, app)
	})
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		protected(w, r)
	})
	http.HandleFunc("/notes", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		notesHandler(w, r, app)
	}, app))

	// Start the server
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func register(w http.ResponseWriter, r *http.Request, app *App) {

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "invalid method", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := app.authService.Register(username, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "User %s registered successfully", username)
}

func (r *UserRepository) Register(username, password string) error {
	hasedPassword, err := hashpasswords(password)
	if err != nil {
		return fmt.Errorf("could not hash password: %v", err)
	}
	_, err = r.db.Exec(`
	INSERT INTO users (username, password_hash)
	VALUES ($1, $2)
`, username, hasedPassword)
	if err != nil {
		return fmt.Errorf("could not save user: %v", err)
	}
	return nil
}

func login(w http.ResponseWriter, r *http.Request, app *App) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Request Method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	sessionToken, csrfToken, err := app.authService.Login(username, password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

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

func (r *UserRepository) Login(username, password string) (string, error) {
	var storedHash string
	err := r.db.QueryRow(`
    SELECT password_hash
    FROM users
    WHERE username = $1
`, username).Scan(&storedHash)

	if err != nil {
		return "", fmt.Errorf("invalid username or password")
	}

	return storedHash, nil
}

func (a *AuthService) Register(username, password string) error {

	if len(username) < 8 || len(password) < 8 {
		return fmt.Errorf("username and password must be at least 8 characters long")
	}
	return a.userRepo.Register(username, password)
}

func (a *AuthService) Login(username, password string) (string, string, error) {

	storedHash, err := a.userRepo.Login(username, password)
	if err != nil {
		return "", "", fmt.Errorf("invalid username or password")
	}
	if !checkPasswordHash(password, storedHash) {
		return "", "", fmt.Errorf("invalid username or password")
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)
	a.sessions[sessionToken] = username
	return sessionToken, csrfToken, nil
}

func logout(w http.ResponseWriter, r *http.Request, app *App) {
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		delete(app.authService.sessions, sessionCookie.Value)
	}

	clearAuthCookies(w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func protected(w http.ResponseWriter, r *http.Request) {}

func mainPage(w http.ResponseWriter, r *http.Request, app *App) {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := app.authService.sessions[sessionCookie.Value]
	search := r.URL.Query().Get("search")

	notes, err := app.noteService.SearchByUser(username, search)
	if err != nil {
		http.Error(w, "could not load notes", http.StatusInternalServerError)
		return
	}

	pageTemplate.Execute(w, PageData{Notes: notes})
}

func fetchUserNotes(app *App, username string) ([]Note, error) {
	rows, err := app.noteService.noteRepo.db.Query(`SELECT title, content
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

func notesHandler(w http.ResponseWriter, r *http.Request, app *App) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")
	if content == "" {
		content = r.FormValue("notes")
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	username := app.authService.sessions[sessionCookie.Value]

	noteservice := &NoteService{noteRepo: NewNoteRepository(app.noteService.noteRepo.db)}

	err = app.noteService.AddNote(username, title, content)
	if err != nil {
		http.Error(w, "could not save note", http.StatusInternalServerError)
		return
	}

	notes, err := noteservice.SearchByUser(username, "")
	if err != nil {
		http.Error(w, "could not load notes", http.StatusInternalServerError)
		return
	}
	pageTemplate.Execute(w, PageData{Message: "Note saved", Notes: notes})
}

func (r *NoteRepository) AddNote(username, title, content string) error {
	_, err := r.db.Exec(`
        INSERT INTO notes (userid, title, content)
        VALUES ((SELECT id FROM users WHERE username = $1), $2, $3)
    `, username, title, content)
	return err
}

func (r *NoteRepository) SearchByUser(username, search string) ([]Note, error) {
	rows, err := r.db.Query(`
		SELECT title, content
		FROM notes
		WHERE userid = (SELECT id FROM users WHERE username = $1)
		AND (title ILIKE $2 OR content ILIKE $2)
		ORDER BY created_at DESC
	`, username, "%"+search+"%")

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

func (s *NoteService) AddNote(username, title, content string) error {
	return s.noteRepo.AddNote(username, title, content)
}

func (s *NoteService) SearchByUser(username, search string) ([]Note, error) {
	return s.noteRepo.SearchByUser(username, search)
}

var migrations = []migration{
	{
		name: "create_users_table",
		sql: `
			CREATE TABLE IF NOT EXISTS users (
				id SERIAL PRIMARY KEY,
				username VARCHAR(255) UNIQUE NOT NULL,
				password_hash VARCHAR(255) NOT NULL
			)
		`,
	},
	{
		name: "create_notes_table",
		sql: `
			CREATE TABLE IF NOT EXISTS notes (
				id SERIAL PRIMARY KEY,
				userid INTEGER REFERENCES users(id),
				title VARCHAR(255) NOT NULL,
				content TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`,
	},
}

func applyMigrations(db *sql.DB) error {
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = $1)", m.name).Scan(&exists)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		if _, err := db.Exec(m.sql); err != nil {
			return err
		}
		if _, err := db.Exec("INSERT INTO schema_migrations (name) VALUES ($1)", m.name); err != nil {
			return err
		}
	}
	return nil
}
