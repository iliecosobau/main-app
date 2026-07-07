package models

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

type Note struct {
	Title   string
	Content string
}

type PageData struct {
	Message string
	Notes   []Note
}
