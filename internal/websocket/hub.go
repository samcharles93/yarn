package websocket

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/models"
)

// Hub maintains the set of active HTMX clients and broadcasts messages to the clients
type Hub struct {
	// Registered HTMX clients
	htmxClients map[*HTMXClient]bool

	// Register requests from HTMX clients
	RegisterHTMX chan *HTMXClient

	// Unregister requests from HTMX clients
	UnregisterHTMX chan *HTMXClient

	// Database connection
	db *database.DB

	// Mutex to protect concurrent access to clients map
	mu sync.RWMutex

	// User presence tracking for HTMX clients
	htmxUserPresence map[uuid.UUID]*HTMXClient // userID -> htmx client

	// Typing status tracking
	typingStatus map[uuid.UUID]map[uuid.UUID]time.Time // userID -> chatPartnerID -> lastTypingTime
	typingMu     sync.RWMutex
}

// NewHub creates a new websocket hub
func NewHub(db *database.DB) *Hub {
	return &Hub{
		htmxClients:      make(map[*HTMXClient]bool),
		RegisterHTMX:     make(chan *HTMXClient),
		UnregisterHTMX:   make(chan *HTMXClient),
		db:               db,
		htmxUserPresence: make(map[uuid.UUID]*HTMXClient),
		typingStatus:     make(map[uuid.UUID]map[uuid.UUID]time.Time),
	}
}

// Run starts the hub and handles client registration/unregistration and message broadcasting
func (h *Hub) Run() {
	// Start a goroutine to clean up expired typing indicators
	go h.cleanupTypingIndicators()

	for {
		select {
		case client := <-h.RegisterHTMX:
			h.registerHTMXClient(client)

		case client := <-h.UnregisterHTMX:
			h.unregisterHTMXClient(client)
		}
	}
}

// registerHTMXClient registers a new HTMX client
func (h *Hub) registerHTMXClient(client *HTMXClient) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.htmxClients[client] = true
	h.htmxUserPresence[client.GetUserID()] = client

	log.Printf("HTMX Client registered: User %s (%s)", client.GetUserID().String(), client.GetUsername())

	// Notify other clients that this user is online
	h.broadcastUserPresence(client.GetUserID(), client.GetUsername(), true)

	// Update user presence in database
	h.updateUserPresence(client.GetUserID(), true)
}

// unregisterHTMXClient unregisters an HTMX client
func (h *Hub) unregisterHTMXClient(client *HTMXClient) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.htmxClients[client]; ok {
		delete(h.htmxClients, client)
		delete(h.htmxUserPresence, client.GetUserID())
		close(client.send)

		log.Printf("HTMX Client unregistered: User %s (%s)", client.GetUserID().String(), client.GetUsername())

		// Notify other clients that this user is offline
		h.broadcastUserPresence(client.GetUserID(), client.GetUsername(), false)

		// Update user presence in database
		h.updateUserPresence(client.GetUserID(), false)

		// Clear typing status for this user
		h.clearUserTypingStatus(client.GetUserID())
	}
}

// sendToHTMXUser sends a message to a specific HTMX user if they're online
func (h *Hub) sendToHTMXUser(userID uuid.UUID, message *WebSocketMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if client, ok := h.htmxUserPresence[userID]; ok {
		// Convert WebSocket message to appropriate HTML fragment
		h.sendHTMLToClient(client, message)
	}
}

// sendHTMLToClient converts a WebSocket message to HTML and sends it to the client
func (h *Hub) sendHTMLToClient(client *HTMXClient, message *WebSocketMessage) {
	switch message.Type {
	case MessageTypeChat:
		client.SendHTML("message", message)
	case MessageTypeTypingStart:
		client.SendHTML("typing", message)
	case MessageTypeTypingStop:
		// Clear typing indicator - send empty HTML or specific clear command
		client.send <- []byte(`<div class="typing-indicator" style="display:none;"></div>`)
	case MessageTypeUserOnline, MessageTypeUserOffline:
		// Update user presence indicator
		client.SendHTML("presence", message)
	case MessageTypeFileUpload:
		client.SendHTML("file", message)
	case MessageTypeHeartbeat:
		// HTMX clients don't need heartbeat HTML updates
		return
	default:
		log.Printf("Unknown message type for HTMX client: %s", message.Type)
	}
}

// broadcastUserPresence broadcasts user presence changes to all HTMX clients
func (h *Hub) broadcastUserPresence(userID uuid.UUID, username string, isOnline bool) {
	presenceData := UserPresenceData{
		UserID:   userID,
		Username: username,
		IsOnline: isOnline,
	}

	message, err := NewWebSocketMessage(MessageTypeUserOnline, presenceData)
	if err != nil {
		log.Printf("Error creating presence message: %v", err)
		return
	}

	if !isOnline {
		message.Type = MessageTypeUserOffline
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling presence message: %v", err)
		return
	}

	// Broadcast to all HTMX clients except the user themselves
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.htmxClients {
		if client.GetUserID() != userID {
			select {
			case client.send <- messageBytes:
			default:
				close(client.send)
				delete(h.htmxClients, client)
			}
		}
	}
}

// clearUserTypingStatus clears all typing status for a user
func (h *Hub) clearUserTypingStatus(userID uuid.UUID) {
	h.typingMu.Lock()
	defer h.typingMu.Unlock()

	// Send typing stop messages to all chat partners
	if partners, ok := h.typingStatus[userID]; ok {
		for chatPartnerID := range partners {
			typingData := TypingData{
				UserID:        userID,
				ChatPartnerID: chatPartnerID,
			}

			message, err := NewWebSocketMessage(MessageTypeTypingStop, typingData)
			if err != nil {
				continue
			}

			h.sendToHTMXUser(chatPartnerID, message)
		}
	}

	delete(h.typingStatus, userID)
}

// cleanupTypingIndicators periodically cleans up expired typing indicators
func (h *Hub) cleanupTypingIndicators() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		h.typingMu.Lock()
		now := time.Now()

		for userID, partners := range h.typingStatus {
			for chatPartnerID, lastTyping := range partners {
				// If typing indicator is older than 10 seconds, remove it
				if now.Sub(lastTyping) > 10*time.Second {
					delete(partners, chatPartnerID)

					// Send typing stop message
					typingData := TypingData{
						UserID:        userID,
						ChatPartnerID: chatPartnerID,
					}

					message, err := NewWebSocketMessage(MessageTypeTypingStop, typingData)
					if err == nil {
						h.sendToHTMXUser(chatPartnerID, message)
					}
				}
			}

			if len(partners) == 0 {
				delete(h.typingStatus, userID)
			}
		}

		h.typingMu.Unlock()
	}
}

// updateUserPresence updates user presence in the database
func (h *Hub) updateUserPresence(userID uuid.UUID, isOnline bool) {
	// This would typically update a user_presence table
	// For now, we'll just log it since we haven't extended the database yet
	log.Printf("User %s presence updated: online=%v", userID.String(), isOnline)
}

// BroadcastNewMessage broadcasts a new message to the recipient if they're online
func (h *Hub) BroadcastNewMessage(msg *models.Message) {
	chatData := ChatMessageData{
		ID:               msg.ID,
		SenderID:         msg.SenderID,
		ReceiverID:       msg.ReceiverID,
		EncryptedContent: base64.StdEncoding.EncodeToString(msg.Content),
		IV:               base64.StdEncoding.EncodeToString(msg.IV),
		Timestamp:        msg.Timestamp.Format(time.RFC3339),
	}

	message, err := NewWebSocketMessage(MessageTypeChat, chatData)
	if err != nil {
		log.Printf("Error creating chat broadcast message: %v", err)
		return
	}

	h.sendToHTMXUser(msg.ReceiverID, message)
}

// BroadcastFileUpload broadcasts a file upload notification
func (h *Hub) BroadcastFileUpload(file *models.File) {
	fileData := FileUploadData{
		FileID:           file.ID,
		SenderID:         file.SenderID,
		ReceiverID:       file.ReceiverID,
		OriginalFilename: file.OriginalFilename,
		Timestamp:        file.Timestamp.Format(time.RFC3339),
	}

	message, err := NewWebSocketMessage(MessageTypeFileUpload, fileData)
	if err != nil {
		log.Printf("Error creating file upload broadcast message: %v", err)
		return
	}

	h.sendToHTMXUser(file.ReceiverID, message)
}

// GetOnlineUsers returns a list of currently online HTMX users
func (h *Hub) GetOnlineUsers() []uuid.UUID {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var onlineUsers []uuid.UUID
	for userID := range h.htmxUserPresence {
		onlineUsers = append(onlineUsers, userID)
	}

	return onlineUsers
}

// IsUserOnline checks if a user is currently online via HTMX
func (h *Hub) IsUserOnline(userID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	_, online := h.htmxUserPresence[userID]
	return online
}

// GetHTMXClient returns an HTMX client by user ID
func (h *Hub) GetHTMXClient(userID uuid.UUID) *HTMXClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.htmxUserPresence[userID]
}
