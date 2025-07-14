package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/internal/models"
)

// SendMessageHandler handles sending encrypted chat messages.
// It expects sender_id, receiver_id, encrypted_content, and iv in the JSON payload.
func (h *Handler) SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SenderID         uuid.UUID `json:"senderId"`
		ReceiverID       uuid.UUID `json:"receiverId"`
		EncryptedContent []byte    `json:"encryptedContent"` // Base64 decoded on client, sent as raw bytes
		IV               []byte    `json:"iv"`               // Base64 decoded on client, sent as raw bytes
	}

	// Decode the JSON request body.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create a new message model.
	msg := &models.Message{
		SenderID:   req.SenderID,
		ReceiverID: req.ReceiverID,
		Content:    req.EncryptedContent,
		IV:         req.IV,
	}

	// Add the encrypted message to the database.
	if err := h.db.AddMessage(msg); err != nil {
		log.Printf("Failed to add message to database: %v", err)
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	// Broadcast the message via websocket if the recipient is online
	if h.wsHub != nil {
		h.wsHub.BroadcastNewMessage(msg)
	}

	// Log metrics for message sent.
	h.db.AddMetric("message_sent")

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Message sent successfully"})
}

// GetMessagesHandler retrieves encrypted chat messages between two users.
// It expects sender_id and receiver_id as query parameters.
func (h *Handler) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	senderIDStr := r.URL.Query().Get("senderId")
	receiverIDStr := r.URL.Query().Get("receiverId")

	senderID, err := uuid.Parse(senderIDStr)
	if err != nil {
		http.Error(w, "Invalid senderId", http.StatusBadRequest)
		return
	}
	receiverID, err := uuid.Parse(receiverIDStr)
	if err != nil {
		http.Error(w, "Invalid receiverId", http.StatusBadRequest)
		return
	}

	messages, err := h.db.GetMessagesBetweenUsers(senderID, receiverID)
	if err != nil {
		log.Printf("Failed to get messages: %v", err)
		http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
		return
	}

	// Prepare messages for JSON response, encoding content and IV to base64.
	var messagesResponse []map[string]interface{}
	for _, msg := range messages {
		messagesResponse = append(messagesResponse, map[string]interface{}{
			"id":               msg.ID,
			"senderId":         msg.SenderID,
			"receiverId":       msg.ReceiverID,
			"encryptedContent": base64.StdEncoding.EncodeToString(msg.Content), // Encode for JSON
			"iv":               base64.StdEncoding.EncodeToString(msg.IV),      // Encode for JSON
			"timestamp":        msg.Timestamp.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messagesResponse)
}
