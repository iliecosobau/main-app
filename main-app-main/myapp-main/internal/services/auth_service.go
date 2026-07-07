package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"myapp/internal/repositories"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo *repositories.UserRepository
	sessions map[string]string
}

func NewAuthService(userRepo *repositories.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo, sessions: map[string]string{}}
}

func (a *AuthService) Register(username, password string) error {
	if len(username) < 8 || len(password) < 8 {
		return fmt.Errorf("username and password must be at least 8 characters long")
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("could not hash password: %v", err)
	}

	return a.userRepo.Register(username, hashedPassword)
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

func (a *AuthService) IsAuthenticated(sessionToken string) bool {
	_, ok := a.sessions[sessionToken]
	return ok
}

func (a *AuthService) UsernameForSession(sessionToken string) (string, bool) {
	username, ok := a.sessions[sessionToken]
	return username, ok
}

func (a *AuthService) Logout(sessionToken string) {
	delete(a.sessions, sessionToken)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
