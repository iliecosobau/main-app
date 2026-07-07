package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"myapp/internal/models"
	"myapp/internal/services"
)

type App struct {
	AuthService *services.AuthService
	NoteService *services.NoteService
	Template    *template.Template
}

func NewApp(authService *services.AuthService, noteService *services.NoteService) *App {
	return &App{
		AuthService: authService,
		NoteService: noteService,
		Template:    template.Must(template.ParseFiles("main.html")),
	}
}

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

func (a *App) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
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

		if !a.AuthService.IsAuthenticated(sessionCookie.Value) {
			clearAuthCookies(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func (a *App) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := a.AuthService.Register(username, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "User %s registered successfully", username)
}

func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Request Method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	sessionToken, csrfToken, err := a.AuthService.Login(username, password)
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

func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		a.AuthService.Logout(sessionCookie.Value)
	}

	clearAuthCookies(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) MainPage(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username, ok := a.AuthService.UsernameForSession(sessionCookie.Value)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	search := r.URL.Query().Get("search")
	notes, err := a.NoteService.SearchByUser(username, search)
	if err != nil {
		http.Error(w, "could not load notes", http.StatusInternalServerError)
		return
	}

	a.Template.Execute(w, models.PageData{Notes: notes})
}

func (a *App) NotesHandler(w http.ResponseWriter, r *http.Request) {
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

	username, ok := a.AuthService.UsernameForSession(sessionCookie.Value)
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}

	if err := a.NoteService.AddNote(username, title, content); err != nil {
		http.Error(w, "could not save note", http.StatusInternalServerError)
		return
	}

	notes, err := a.NoteService.SearchByUser(username, "")
	if err != nil {
		http.Error(w, "could not load notes", http.StatusInternalServerError)
		return
	}

	a.Template.Execute(w, models.PageData{Message: "Note saved", Notes: notes})
}

func (a *App) Protected(w http.ResponseWriter, r *http.Request) {}
