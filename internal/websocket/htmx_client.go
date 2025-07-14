package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/samcharles93/yarn/internal/database"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512
)

// HTMXClient represents a WebSocket client that sends HTML fragments for HTMX
type HTMXClient struct {
	// The websocket connection
	conn *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte

	// The hub that manages this client
	hub *Hub

	// User ID associated with this client
	userID uuid.UUID

	// Username associated with this client
	username string

	// Database connection for fetching data
	db *database.DB

	// Mutex to protect concurrent access
	mu sync.RWMutex

	// Whether the client is authenticated
	authenticated bool
}

// NewHTMXClient creates a new HTMX WebSocket client
func NewHTMXClient(hub *Hub, conn *websocket.Conn, userID uuid.UUID, username string, db *database.DB) *HTMXClient {
	return &HTMXClient{
		conn:          conn,
		send:          make(chan []byte, 256),
		hub:           hub,
		userID:        userID,
		username:      username,
		db:            db,
		authenticated: true,
	}
}

// GetUserID returns the user ID for this client
func (c *HTMXClient) GetUserID() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userID
}

// GetUsername returns the username for this client
func (c *HTMXClient) GetUsername() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.username
}

// IsAuthenticated returns whether the client is authenticated
func (c *HTMXClient) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authenticated
}

// ReadPump pumps messages from the websocket connection to the hub
func (c *HTMXClient) ReadPump() {
	defer func() {
		c.hub.UnregisterHTMX <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("websocket error: %v", err)
			}
			break
		}

		// Parse the incoming message as JSON
		var message map[string]interface{}
		if err := json.Unmarshal(messageBytes, &message); err != nil {
			log.Printf("Error parsing websocket message: %v", err)
			c.SendError("Invalid message format")
			continue
		}

		// Extract message type and data
		msgType, ok := message["type"].(string)
		if !ok {
			c.SendError("Missing message type")
			continue
		}

		// Handle the message based on its type
		c.handleMessage(msgType, message)
	}
}

// WritePump pumps messages from the hub to the websocket connection
func (c *HTMXClient) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current websocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// SendHTML sends an HTML fragment to this client
func (c *HTMXClient) SendHTML(elementType string, component interface{}) {
	// This is a placeholder - in real implementation, you'd render the Templ component
	// For now, we'll send a simple HTML fragment
	var html string
	switch elementType {
	case "message":
		html = `<div class="message received"><div class="message-bubble"><p>New message received</p></div></div>`
	case "typing":
		html = `<div class="typing-indicator">Someone is typing...</div>`
	default:
		html = `<div>Unknown update</div>`
	}

	c.send <- []byte(html)
}

// SendError sends an error message to this client
func (c *HTMXClient) SendError(errorMsg string) {
	html := `<div class="message-box error">` + errorMsg + `</div>`
	c.send <- []byte(html)
}

// handleMessage processes incoming messages
func (c *HTMXClient) handleMessage(msgType string, _ map[string]any) {
	// This would be handled by the main handler
	// For now, just log the message
	log.Printf("HTMX Client received message type: %s from user %s", msgType, c.username)
}

// UpgradeConnection upgrades an HTTP connection to WebSocket
func UpgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// Allow connections from any origin for now
			// In production, you should validate the origin
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
