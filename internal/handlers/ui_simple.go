package handlers

import (
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/UI/components"
	"github.com/samcharles93/yarn/internal/models"
)

// SimpleUIHandler serves the new modern UI with basic functionality
func (h *Handler) SimpleUIHandler(w http.ResponseWriter, r *http.Request) {
	// Check for existing session
	var currentUser *models.User
	if sess, exists := h.sessionMgr.GetSessionFromRequest(r); exists {
		currentUser = sess.User
	}

	users, err := h.db.GetAllUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		users = []*models.User{}
	}

	// Render the main page with current user (or nil if not authenticated)
	component := components.MainPage(currentUser, users)
	component.Render(r.Context(), w)
}

// SimpleAPIRegisterHandler handles user registration via HTMX
func (h *Handler) SimpleAPIRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	bio := r.FormValue("bio")

	if username == "" {
		component := components.AuthMessage("Username cannot be empty", "error")
		component.Render(r.Context(), w)
		return
	}

	// Check if user already exists
	existingUser, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		component := components.AuthMessage("Internal server error", "error")
		component.Render(r.Context(), w)
		return
	}
	if existingUser != nil {
		component := components.AuthMessage("Username already taken", "error")
		component.Render(r.Context(), w)
		return
	}

	// Create a user with a dummy public key
	user := &models.User{
		Username:  username,
		Bio:       bio,
		PublicKey: []byte("dummy_key_" + username), // Placeholder
	}

	if err := h.db.AddUser(user); err != nil {
		log.Printf("Failed to add user: %v", err)
		component := components.AuthMessage("Failed to register user", "error")
		component.Render(r.Context(), w)
		return
	}

	// Create session for the user
	sess, err := h.sessionMgr.CreateSession(user)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		component := components.AuthMessage("Failed to create session", "error")
		component.Render(r.Context(), w)
		return
	}

	// Set session cookie
	h.sessionMgr.SetSessionCookie(w, sess)

	// Log metrics
	h.db.AddMetric("user_registered")

	// Return success component
	component := components.AuthSuccess(user)
	component.Render(r.Context(), w)
}

// SimpleAPILoginHandler handles user login via HTMX
func (h *Handler) SimpleAPILoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		component := components.AuthMessage("Username cannot be empty", "error")
		component.Render(r.Context(), w)
		return
	}

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("Error retrieving user: %v", err)
		component := components.AuthMessage("Internal server error", "error")
		component.Render(r.Context(), w)
		return
	}
	if user == nil {
		component := components.AuthMessage("User not found", "error")
		component.Render(r.Context(), w)
		return
	}

	// Create session for the user
	sess, err := h.sessionMgr.CreateSession(user)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		component := components.AuthMessage("Failed to create session", "error")
		component.Render(r.Context(), w)
		return
	}

	// Set session cookie
	h.sessionMgr.SetSessionCookie(w, sess)

	// Return success component
	component := components.LoginSuccess(user)
	component.Render(r.Context(), w)
}

// SimpleAPIChatHandler handles chat area updates
func (h *Handler) SimpleAPIChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract partner ID from URL path
	partnerIDStr := r.URL.Path[len("/api/chat/"):]
	partnerID, err := uuid.Parse(partnerIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get partner user
	partner, err := h.db.GetUserByID(partnerID)
	if err != nil {
		log.Printf("Error getting partner: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if partner == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get current user from session
	sess, exists := h.sessionMgr.GetSessionFromRequest(r)
	if !exists {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Get messages between users - for now, return empty messages
	messages := []*models.Message{}

	// Render chat area
	component := components.ChatArea(partner, messages, sess.User)
	component.Render(r.Context(), w)
}

// SimpleAPILogoutHandler handles user logout
func (h *Handler) SimpleAPILogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session and delete it
	if sess, exists := h.sessionMgr.GetSessionFromRequest(r); exists {
		h.sessionMgr.DeleteSession(sess.ID)
	}

	// Clear session cookie
	h.sessionMgr.ClearSessionCookie(w)

	// Get all users for the logged-out page
	users, err := h.db.GetAllUsers()
	if err != nil {
		log.Printf("Error getting users: %v", err)
		users = []*models.User{}
	}

	// Return the main page with no authenticated user
	component := components.MainPage(nil, users)
	component.Render(r.Context(), w)
}
