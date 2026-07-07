package main

import (
	"database/sql"
	"log"
	"net/http"

	"myapp/internal/db"
	"myapp/internal/handlers"
	"myapp/internal/repositories"
	"myapp/internal/services"

	_ "github.com/lib/pq"
)

func main() {
	connStr := "postgres://postgres:secret@localhost:5432/gopgtest?sslmode=disable"

	database, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	if err = database.Ping(); err != nil {
		log.Fatal(err)
	}

	if err := db.ApplyMigrations(database); err != nil {
		log.Fatal(err)
	}

	userRepo := repositories.NewUserRepository(database)
	authService := services.NewAuthService(userRepo)
	noteRepo := repositories.NewNoteRepository(database)
	noteService := services.NewNoteService(noteRepo)
	app := handlers.NewApp(authService, noteService)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/main", app.RequireAuth(app.MainPage))
	http.HandleFunc("/register", app.Register)
	http.HandleFunc("/login", app.Login)
	http.HandleFunc("/logout", app.Logout)
	http.HandleFunc("/protected", app.Protected)
	http.HandleFunc("/notes", app.RequireAuth(app.NotesHandler))

	log.Fatal(http.ListenAndServe(":8000", nil))
}
