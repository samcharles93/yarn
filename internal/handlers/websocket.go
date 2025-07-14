package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/samcharles93/yarn/internal/websocket"
)

// WebSocketHandler handles websocket connection requests
func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from query parameters (in a real app, this would come from session/JWT)
	userIDStr := r.URL.Query().Get("userId")
	username := r.URL.Query().Get("username")

	if userIDStr == "" || username == "" {
		http.Error(w, "Missing userId or username", http.StatusBadRequest)
		return
	}

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid userId", http.StatusBadRequest)
		return
	}

	// Verify user exists in database
	user, err := h.db.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user for websocket: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Verify username matches
	if user.Username != username {
		http.Error(w, "Username mismatch", http.StatusUnauthorized)
		return
	}

	// Upgrade to websocket connection
	websocket.ServeWS(h.wsHub, w, r, userID, username)
}
