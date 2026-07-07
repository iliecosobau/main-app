package repositories

import (
	"database/sql"
	"fmt"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Register(username, password string) error {
	_, err := r.db.Exec(`
		INSERT INTO users (username, password_hash)
		VALUES ($1, $2)
	`, username, password)
	if err != nil {
		return fmt.Errorf("could not save user: %v", err)
	}
	return nil
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
