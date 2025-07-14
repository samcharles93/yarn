package handlers

import (
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/UI/components"
	"github.com/samcharles93/yarn/internal/models"
	"github.com/samcharles93/yarn/internal/websocket"
)

// HTMXWebSocketHandler handles WebSocket connections that send HTML fragments for HTMX
func (h *Handler) HTMXWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.URL.Query().Get("userId")
	username := r.URL.Query().Get("username")

	if userIDStr == "" || username == "" {
		http.Error(w, "Missing userId or username", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(userIDStr)
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

	// Create a custom WebSocket connection that sends HTML instead of JSON
	conn, err := websocket.UpgradeConnection(w, r)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Create a custom client that handles HTMX responses
	client := websocket.NewHTMXClient(h.wsHub, conn, userID, username, h.db)
	h.wsHub.RegisterHTMX <- client

	// Allow collection of memory referenced by the caller by doing all work in new goroutines
	go client.WritePump()
	go client.ReadPump()
}

// HandleWebSocketMessage processes incoming WebSocket messages and sends HTML responses
func (h *Handler) HandleWebSocketMessage(client *websocket.HTMXClient, msgType string, data map[string]interface{}) {
	switch msgType {
	case "chat":
		h.handleChatMessage(client, data)
	case "typing_start":
		h.handleTypingStart(client, data)
	case "typing_stop":
		h.handleTypingStop(client, data)
	default:
		log.Printf("Unknown message type: %s", msgType)
	}
}

func (h *Handler) handleChatMessage(client *websocket.HTMXClient, data map[string]interface{}) {
	receiverIDStr, ok := data["receiverId"].(string)
	if !ok {
		client.SendError("Invalid receiverId")
		return
	}

	receiverID, err := uuid.Parse(receiverIDStr)
	if err != nil {
		client.SendError("Invalid receiverId format")
		return
	}

	message, ok := data["message"].(string)
	if !ok || message == "" {
		client.SendError("Invalid message")
		return
	}

	// For now, store unencrypted message (encryption will be added later)
	// In production, this would be encrypted content
	newMessage := &models.Message{
		ID:         uuid.New(),
		SenderID:   client.GetUserID(),
		ReceiverID: receiverID,
		Content:    []byte(message),    // This should be encrypted
		IV:         []byte("dummy_iv"), // This should be real IV
	}

	// Save message to database
	if err := h.db.AddMessage(newMessage); err != nil {
		log.Printf("Failed to save message: %v", err)
		client.SendError("Failed to send message")
		return
	}

	// Send HTML fragment to sender (you)
	senderHTML := components.NewMessage(newMessage, client.GetUserID(), "You")
	client.SendHTML("message", senderHTML)

	// Send HTML fragment to receiver if they're online
	if receiverClient := h.wsHub.GetHTMXClient(receiverID); receiverClient != nil {
		receiverHTML := components.NewMessage(newMessage, receiverID, client.GetUsername())
		receiverClient.SendHTML("message", receiverHTML)
	}

	// Log metrics
	h.db.AddMetric("message_sent")
}

func (h *Handler) handleTypingStart(client *websocket.HTMXClient, data map[string]interface{}) {
	receiverIDStr, ok := data["receiverId"].(string)
	if !ok {
		return
	}

	receiverID, err := uuid.Parse(receiverIDStr)
	if err != nil {
		return
	}

	// Send typing indicator to receiver if they're online
	if receiverClient := h.wsHub.GetHTMXClient(receiverID); receiverClient != nil {
		typingHTML := components.WebSocketTypingIndicator(client.GetUsername(), true)
		receiverClient.SendHTML("typing", typingHTML)
	}
}

func (h *Handler) handleTypingStop(client *websocket.HTMXClient, data map[string]interface{}) {
	receiverIDStr, ok := data["receiverId"].(string)
	if !ok {
		return
	}

	receiverID, err := uuid.Parse(receiverIDStr)
	if err != nil {
		return
	}

	// Send typing stop to receiver if they're online
	if receiverClient := h.wsHub.GetHTMXClient(receiverID); receiverClient != nil {
		typingHTML := components.WebSocketTypingIndicator(client.GetUsername(), false)
		receiverClient.SendHTML("typing", typingHTML)
	}
}
