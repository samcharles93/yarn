package websocket

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/models"
)

// Hub maintains the set of active clients and broadcasts messages to the clients
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// Inbound messages from the clients
	broadcast chan []byte

	// Register requests from the clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Database connection
	db *database.DB

	// Mutex to protect concurrent access to clients map
	mu sync.RWMutex

	// User presence tracking
	userPresence map[int]*Client // userID -> client

	// Typing status tracking
	typingStatus map[int]map[int]time.Time // userID -> chatPartnerID -> lastTypingTime
	typingMu     sync.RWMutex
}

// NewHub creates a new websocket hub
func NewHub(db *database.DB) *Hub {
	return &Hub{
		clients:      make(map[*Client]bool),
		broadcast:    make(chan []byte),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		db:           db,
		userPresence: make(map[int]*Client),
		typingStatus: make(map[int]map[int]time.Time),
	}
}

// Run starts the hub and handles client registration/unregistration and message broadcasting
func (h *Hub) Run() {
	// Start a goroutine to clean up expired typing indicators
	go h.cleanupTypingIndicators()

	for {
		select {
		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case message := <-h.broadcast:
			h.broadcastMessage(message)
		}
	}
}

// registerClient registers a new client
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client] = true
	h.userPresence[client.GetUserID()] = client

	log.Printf("Client registered: User %d (%s)", client.GetUserID(), client.GetUsername())

	// Notify other clients that this user is online
	h.broadcastUserPresence(client.GetUserID(), client.GetUsername(), true)

	// Update user presence in database
	h.updateUserPresence(client.GetUserID(), true)
}

// unregisterClient unregisters a client
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		delete(h.userPresence, client.GetUserID())
		close(client.send)

		log.Printf("Client unregistered: User %d (%s)", client.GetUserID(), client.GetUsername())

		// Notify other clients that this user is offline
		h.broadcastUserPresence(client.GetUserID(), client.GetUsername(), false)

		// Update user presence in database
		h.updateUserPresence(client.GetUserID(), false)

		// Clear typing status for this user
		h.clearUserTypingStatus(client.GetUserID())
	}
}

// broadcastMessage broadcasts a message to all connected clients
func (h *Hub) broadcastMessage(message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- message:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
}

// handleMessage handles incoming websocket messages
func (h *Hub) handleMessage(client *Client, message *WebSocketMessage) {
	switch message.Type {
	case MessageTypeChat:
		h.handleChatMessage(client, message)
	case MessageTypeTypingStart:
		h.handleTypingStart(client, message)
	case MessageTypeTypingStop:
		h.handleTypingStop(client, message)
	case MessageTypeHeartbeat:
		h.handleHeartbeat(client, message)
	default:
		log.Printf("Unknown message type: %s", message.Type)
		client.sendError("Unknown message type")
	}
}

// handleChatMessage handles chat messages
func (h *Hub) handleChatMessage(client *Client, message *WebSocketMessage) {
	var chatData ChatMessageData
	if err := message.ParseData(&chatData); err != nil {
		log.Printf("Error parsing chat message: %v", err)
		client.sendError("Invalid chat message format")
		return
	}

	// Verify the sender ID matches the client
	if chatData.SenderID != client.GetUserID() {
		client.sendError("Sender ID mismatch")
		return
	}

	// Send the message to the specific recipient if they're online
	h.sendToUser(chatData.ReceiverID, message)

	log.Printf("Chat message from %d to %d", chatData.SenderID, chatData.ReceiverID)
}

// handleTypingStart handles typing start events
func (h *Hub) handleTypingStart(client *Client, message *WebSocketMessage) {
	var typingData TypingData
	if err := message.ParseData(&typingData); err != nil {
		log.Printf("Error parsing typing start message: %v", err)
		client.sendError("Invalid typing message format")
		return
	}

	// Update typing status
	h.setTypingStatus(client.GetUserID(), typingData.ChatPartnerID, true)

	// Send typing indicator to the chat partner
	typingData.UserID = client.GetUserID()
	typingData.Username = client.GetUsername()

	typingMessage, err := NewWebSocketMessage(MessageTypeTypingStart, typingData)
	if err != nil {
		log.Printf("Error creating typing message: %v", err)
		return
	}

	h.sendToUser(typingData.ChatPartnerID, typingMessage)
}

// handleTypingStop handles typing stop events
func (h *Hub) handleTypingStop(client *Client, message *WebSocketMessage) {
	var typingData TypingData
	if err := message.ParseData(&typingData); err != nil {
		log.Printf("Error parsing typing stop message: %v", err)
		client.sendError("Invalid typing message format")
		return
	}

	// Update typing status
	h.setTypingStatus(client.GetUserID(), typingData.ChatPartnerID, false)

	// Send typing stop indicator to the chat partner
	typingData.UserID = client.GetUserID()
	typingData.Username = client.GetUsername()

	typingMessage, err := NewWebSocketMessage(MessageTypeTypingStop, typingData)
	if err != nil {
		log.Printf("Error creating typing stop message: %v", err)
		return
	}

	h.sendToUser(typingData.ChatPartnerID, typingMessage)
}

// handleHeartbeat handles heartbeat messages
func (h *Hub) handleHeartbeat(client *Client, message *WebSocketMessage) {
	// Update last seen time in database
	h.updateUserPresence(client.GetUserID(), true)

	// Send heartbeat response
	heartbeatData := HeartbeatData{
		Timestamp: time.Now(),
	}

	response, err := NewWebSocketMessage(MessageTypeHeartbeat, heartbeatData)
	if err != nil {
		log.Printf("Error creating heartbeat response: %v", err)
		return
	}

	client.sendMessage(response)
}

// sendToUser sends a message to a specific user if they're online
func (h *Hub) sendToUser(userID int, message *WebSocketMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if client, ok := h.userPresence[userID]; ok {
		client.sendMessage(message)
	}
}

// broadcastUserPresence broadcasts user presence changes to all clients
func (h *Hub) broadcastUserPresence(userID int, username string, isOnline bool) {
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

	// Broadcast to all clients except the user themselves
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if client.GetUserID() != userID {
			select {
			case client.send <- messageBytes:
			default:
				close(client.send)
				delete(h.clients, client)
			}
		}
	}
}

// setTypingStatus sets the typing status for a user
func (h *Hub) setTypingStatus(userID, chatPartnerID int, isTyping bool) {
	h.typingMu.Lock()
	defer h.typingMu.Unlock()

	if h.typingStatus[userID] == nil {
		h.typingStatus[userID] = make(map[int]time.Time)
	}

	if isTyping {
		h.typingStatus[userID][chatPartnerID] = time.Now()
	} else {
		delete(h.typingStatus[userID], chatPartnerID)
		if len(h.typingStatus[userID]) == 0 {
			delete(h.typingStatus, userID)
		}
	}
}

// clearUserTypingStatus clears all typing status for a user
func (h *Hub) clearUserTypingStatus(userID int) {
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

			h.sendToUser(chatPartnerID, message)
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
						h.sendToUser(chatPartnerID, message)
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
func (h *Hub) updateUserPresence(userID int, isOnline bool) {
	// This would typically update a user_presence table
	// For now, we'll just log it since we haven't extended the database yet
	log.Printf("User %d presence updated: online=%v", userID, isOnline)
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

	h.sendToUser(msg.ReceiverID, message)
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

	h.sendToUser(file.ReceiverID, message)
}

// GetOnlineUsers returns a list of currently online users
func (h *Hub) GetOnlineUsers() []int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var onlineUsers []int
	for userID := range h.userPresence {
		onlineUsers = append(onlineUsers, userID)
	}

	return onlineUsers
}

// IsUserOnline checks if a user is currently online
func (h *Hub) IsUserOnline(userID int) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	_, online := h.userPresence[userID]
	return online
}
