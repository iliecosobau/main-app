package db

import (
	"database/sql"
)

type Migration struct {
	Name string
	SQL  string
}

var Migrations = []Migration{
	{
		Name: "create_users_table",
		SQL: `
			CREATE TABLE IF NOT EXISTS users (
				id SERIAL PRIMARY KEY,
				username VARCHAR(255) UNIQUE NOT NULL,
				password_hash VARCHAR(255) NOT NULL
			)
		`,
	},
	{
		Name: "create_notes_table",
		SQL: `
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

func ApplyMigrations(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return err
	}
	for _, m := range Migrations {
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = $1)", m.Name).Scan(&exists)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		if _, err := db.Exec(m.SQL); err != nil {
			return err
		}
		if _, err := db.Exec("INSERT INTO schema_migrations (name) VALUES ($1)", m.Name); err != nil {
			return err
		}
	}
	return nil
}
