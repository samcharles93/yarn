package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/samcharles93/yarn/internal/models"
)

// RegisterUserHandler handles new user registration.
// It expects a JSON payload with username and bio.
// It generates an ECDH key pair for the user and stores the public key in the database.
func (h *Handler) RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username  string `json:"username"`
		Bio       string `json:"bio"`
		PublicKey []byte `json:"publicKey"` // Public key sent from client
	}

	// Decode the JSON request body.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check if username already exists.
	existingUser, err := h.db.GetUserByUsername(req.Username)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	// Create a new user model.
	user := &models.User{
		Username:  req.Username,
		Bio:       req.Bio,
		PublicKey: req.PublicKey, // Use the public key sent from the client
	}

	// Add the user to the database.
	if err := h.db.AddUser(user); err != nil {
		log.Printf("Failed to add user to database: %v", err)
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Log metrics for user registration.
	h.db.AddMetric("user_registered")

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "User registered successfully",
		"userId":   user.ID,
		"username": user.Username,
	})
}

// LoginHandler handles user login.
// For this basic example, it simply checks if the user exists and returns their ID and public key.
// In a real app, this would involve password hashing and session management.
func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByUsername(req.Username)
	if err != nil {
		log.Printf("Error retrieving user for login: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// For simplicity, we're returning the user ID and public key.
	// In a real application, a session token would be created and returned.
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Login successful",
		"userId":    user.ID,
		"username":  user.Username,
		"publicKey": base64.StdEncoding.EncodeToString(user.PublicKey), // Encode public key to base64 for JSON
	})
}

// GetUsersHandler retrieves a list of all registered users.
func (h *Handler) GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := h.db.GetAllUsers()
	if err != nil {
		log.Printf("Failed to get all users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Prepare users for JSON response, encoding public keys.
	var usersResponse []map[string]interface{}
	for _, user := range users {
		usersResponse = append(usersResponse, map[string]interface{}{
			"id":        user.ID,
			"username":  user.Username,
			"bio":       user.Bio,
			"publicKey": base64.StdEncoding.EncodeToString(user.PublicKey),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usersResponse)
}
