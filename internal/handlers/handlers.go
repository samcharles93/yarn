package handlers

import (
	"html/template"
	"sync"

	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/websocket"
)

// Handler holds the database connection and templates for HTTP handlers.
type Handler struct {
	db   *database.DB
	tmpl *template.Template
	// A simple in-memory map to store current user sessions.
	// In a real application, this would be a more robust session management system.
	userSessions sync.Map // map[string]int (sessionID -> userID)
	// WebSocket hub for real-time communication
	wsHub *websocket.Hub
}

// NewHandler creates and returns a new Handler instance.
func NewHandler(db *database.DB, tmpl *template.Template, wsHub *websocket.Hub) *Handler {
	return &Handler{
		db:           db,
		tmpl:         tmpl,
		userSessions: sync.Map{},
		wsHub:        wsHub,
	}
}
