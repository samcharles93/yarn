package handlers

import (
	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/session"
	"github.com/samcharles93/yarn/internal/websocket"
)

// Handler holds the database connection and session manager for HTTP handlers.
type Handler struct {
	db         *database.DB
	sessionMgr *session.Manager
	// WebSocket hub for real-time communication
	wsHub *websocket.Hub
}

// NewHandler creates and returns a new Handler instance.
func NewHandler(db *database.DB, wsHub *websocket.Hub) *Handler {
	return &Handler{
		db:         db,
		sessionMgr: session.NewManager(),
		wsHub:      wsHub,
	}
}
