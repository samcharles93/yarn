package websocket

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MessageType represents different types of websocket messages
type MessageType string

const (
	// Message types
	MessageTypeChat        MessageType = "chat"
	MessageTypeTypingStart MessageType = "typing_start"
	MessageTypeTypingStop  MessageType = "typing_stop"
	MessageTypeUserOnline  MessageType = "user_online"
	MessageTypeUserOffline MessageType = "user_offline"
	MessageTypeFileUpload  MessageType = "file_upload"
	MessageTypeHeartbeat   MessageType = "heartbeat"
	MessageTypeError       MessageType = "error"
)

// WebSocketMessage represents a message sent over websocket
type WebSocketMessage struct {
	Type      MessageType     `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
	From      uuid.UUID       `json:"from,omitempty"`
	To        uuid.UUID       `json:"to,omitempty"`
}

// ChatMessageData represents the data for a chat message
type ChatMessageData struct {
	ID               uuid.UUID `json:"id"`
	SenderID         uuid.UUID `json:"senderId"`
	ReceiverID       uuid.UUID `json:"receiverId"`
	EncryptedContent string    `json:"encryptedContent"`
	IV               string    `json:"iv"`
	Timestamp        string    `json:"timestamp"`
}

// TypingData represents typing indicator data
type TypingData struct {
	UserID        uuid.UUID `json:"userId"`
	Username      string    `json:"username"`
	ChatPartnerID uuid.UUID `json:"chatPartnerId"`
}

// UserPresenceData represents user presence data
type UserPresenceData struct {
	UserID   uuid.UUID `json:"userId"`
	Username string    `json:"username"`
	IsOnline bool      `json:"isOnline"`
}

// FileUploadData represents file upload notification data
type FileUploadData struct {
	FileID           uuid.UUID `json:"fileId"`
	SenderID         uuid.UUID `json:"senderId"`
	ReceiverID       uuid.UUID `json:"receiverId"`
	OriginalFilename string    `json:"originalFilename"`
	Timestamp        string    `json:"timestamp"`
}

// ErrorData represents error message data
type ErrorData struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// HeartbeatData represents heartbeat data
type HeartbeatData struct {
	Timestamp time.Time `json:"timestamp"`
}

// NewWebSocketMessage creates a new websocket message
func NewWebSocketMessage(msgType MessageType, data any) (*WebSocketMessage, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return &WebSocketMessage{
		Type:      msgType,
		Data:      dataBytes,
		Timestamp: time.Now(),
	}, nil
}

// ParseData parses the message data into the specified type
func (m *WebSocketMessage) ParseData(v any) error {
	return json.Unmarshal(m.Data, v)
}
