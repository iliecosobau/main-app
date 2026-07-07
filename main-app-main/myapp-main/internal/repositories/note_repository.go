package repositories

import (
	"database/sql"

	"myapp/internal/models"
)

type NoteRepository struct {
	db *sql.DB
}

func NewNoteRepository(db *sql.DB) *NoteRepository {
	return &NoteRepository{db: db}
}

func (r *NoteRepository) AddNote(username, title, content string) error {
	_, err := r.db.Exec(`
		INSERT INTO notes (userid, title, content)
		VALUES ((SELECT id FROM users WHERE username = $1), $2, $3)
	`, username, title, content)
	return err
}

func (r *NoteRepository) SearchByUser(username, search string) ([]models.Note, error) {
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

	var notes []models.Note
	for rows.Next() {
		var note models.Note
		if err := rows.Scan(&note.Title, &note.Content); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}
	return notes, rows.Err()
}
