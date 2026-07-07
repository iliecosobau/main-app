package services

import (
	"myapp/internal/models"
	"myapp/internal/repositories"
)

type NoteService struct {
	noteRepo *repositories.NoteRepository
}

func NewNoteService(noteRepo *repositories.NoteRepository) *NoteService {
	return &NoteService{noteRepo: noteRepo}
}

func (s *NoteService) AddNote(username, title, content string) error {
	return s.noteRepo.AddNote(username, title, content)
}

func (s *NoteService) SearchByUser(username, search string) ([]models.Note, error) {
	return s.noteRepo.SearchByUser(username, search)
}
