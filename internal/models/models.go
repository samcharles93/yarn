package models

import "time"

// User represents a user in the Yarn application.
// Only fields explicitly marked as unencrypted (Username, Bio, PublicKey) are stored as plain text.
// The PublicKey is essential for ECDH key exchange.
type User struct {
	ID        int       `json:"id"`        // Unique identifier for the user.
	Username  string    `json:"username"`  // User's chosen username (unencrypted).
	Bio       string    `json:"bio"`       // User's biography (unencrypted, user-editable).
	PublicKey []byte    `json:"publicKey"` // User's ECDH public key (unencrypted, used for key exchange).
	CreatedAt time.Time `json:"createdAt"` // Timestamp when the user was created.
}

// Message represents an encrypted chat message.
// The Content is encrypted, and IV (Initialization Vector) is stored alongside it for decryption.
type Message struct {
	ID         int       `json:"id"`         // Unique identifier for the message.
	SenderID   int       `json:"senderId"`   // ID of the user who sent the message.
	ReceiverID int       `json:"receiverId"` // ID of the user who is the intended recipient.
	Content    []byte    `json:"content"`    // Encrypted message content.
	IV         []byte    `json:"iv"`         // Initialization Vector used for AES-GCM decryption.
	Timestamp  time.Time `json:"timestamp"`  // Timestamp when the message was sent.
}

// File represents an encrypted file shared between users.
// The FilePath points to the location of the encrypted file on the server.
// The IV is stored for decryption. OriginalFilename is unencrypted for display.
type File struct {
	ID               int       `json:"id"`               // Unique identifier for the file.
	SenderID         int       `json:"senderId"`         // ID of the user who sent the file.
	ReceiverID       int       `json:"receiverId"`       // ID of the user who is the intended recipient.
	OriginalFilename string    `json:"originalFilename"` // Original name of the file (unencrypted for display).
	FilePath         string    `json:"filePath"`         // Path to the encrypted file on the server.
	IV               []byte    `json:"iv"`               // Initialization Vector used for AES-GCM decryption.
	Timestamp        time.Time `json:"timestamp"`        // Timestamp when the file was uploaded.
}

// Metrics represents non-identifiable metrics collected for improvements.
// This is a placeholder for future metric collection.
type Metric struct {
	ID        int       `json:"id"`        // Unique identifier for the metric entry.
	EventType string    `json:"eventType"` // Type of event (e.g., "message_sent", "file_uploaded").
	Timestamp time.Time `json:"timestamp"` // Timestamp of the event.
	// Add more non-identifiable fields as needed, e.g., "payload_size", "duration_ms"
}
