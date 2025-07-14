package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/internal/models"

	_ "modernc.org/sqlite"
)

// DB represents the database connection.
type DB struct {
	*sql.DB
	mu sync.Mutex // Mutex to protect concurrent database access
}

// InitDB initializes the SQLite database and creates necessary tables if they don't exist.
func InitDB(dataSourceName string) (*DB, error) {
	// Ensure the directory for the database file exists.
	dbDir := filepath.Dir(dataSourceName)
	if dbDir != "" {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Open the database connection.
	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Ping the database to verify the connection.
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create tables if they don't exist.
	if err = createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	log.Printf("Database initialized: %s", dataSourceName)
	return &DB{DB: db}, nil
}

// createTables creates the 'users', 'messages', 'files', and 'metrics' tables.
func createTables(db *sql.DB) error {
	// SQL statement to create the users table.
	// PublicKey is stored as BLOB (byte array).
	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		bio TEXT,
		public_key BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// SQL statement to create the messages table.
	// Content and IV are stored as BLOBs.
	createMessagesTableSQL := `
	CREATE TABLE IF NOT EXISTS messages (
		id TEXT PRIMARY KEY,
		sender_id TEXT NOT NULL,
		receiver_id TEXT NOT NULL,
		content BLOB NOT NULL,
		iv BLOB NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (sender_id) REFERENCES users(id),
		FOREIGN KEY (receiver_id) REFERENCES users(id)
	);`

	// SQL statement to create the files table.
	// FilePath and IV are stored as BLOBs.
	createFilesTableSQL := `
	CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		sender_id TEXT NOT NULL,
		receiver_id TEXT NOT NULL,
		original_filename TEXT NOT NULL,
		file_path TEXT NOT NULL,
		iv BLOB NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (sender_id) REFERENCES users(id),
		FOREIGN KEY (receiver_id) REFERENCES users(id)
	);`

	// SQL statement to create the metrics table (for non-identifiable metrics).
	createMetricsTableSQL := `
	CREATE TABLE IF NOT EXISTS metrics (
		id TEXT PRIMARY KEY,
		event_type TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Execute the table creation SQL statements.
	_, err := db.Exec(createUsersTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	_, err = db.Exec(createMessagesTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create messages table: %w", err)
	}
	_, err = db.Exec(createFilesTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create files table: %w", err)
	}
	_, err = db.Exec(createMetricsTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create metrics table: %w", err)
	}

	return nil
}

// AddUser inserts a new user into the database.
func (d *DB) AddUser(user *models.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Generate UUID for the user
	user.ID = uuid.New()

	stmt, err := d.Prepare("INSERT INTO users(id, username, bio, public_key) VALUES(?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement for adding user: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.ID.String(), user.Username, user.Bio, user.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to execute statement for adding user: %w", err)
	}

	log.Printf("Added user: %s with ID: %s", user.Username, user.ID.String())
	return nil
}

// GetUserByUsername retrieves a user by their username.
func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.QueryRow("SELECT id, username, bio, public_key, created_at FROM users WHERE username = ?", username)
	user := &models.User{}
	var createdAtStr string
	var idStr string
	err := row.Scan(&idStr, &user.Username, &user.Bio, &user.PublicKey, &createdAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan user by username: %w", err)
	}

	// Parse UUID from string
	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	user.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at for user: %w", err)
	}
	return user, nil
}

// GetUserByID retrieves a user by their ID.
func (d *DB) GetUserByID(id uuid.UUID) (*models.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.QueryRow("SELECT id, username, bio, public_key, created_at FROM users WHERE id = ?", id.String())
	user := &models.User{}
	var createdAtStr string
	var idStr string
	err := row.Scan(&idStr, &user.Username, &user.Bio, &user.PublicKey, &createdAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan user by ID: %w", err)
	}

	// Parse UUID from string
	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	user.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at for user: %w", err)
	}
	return user, nil
}

// GetAllUsers retrieves all users from the database.
func (d *DB) GetAllUsers() ([]*models.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.Query("SELECT id, username, bio, public_key, created_at FROM users")
	if err != nil {
		return nil, fmt.Errorf("failed to query all users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := models.User{}
		var createdAtStr string
		var idStr string
		if err := rows.Scan(&idStr, &user.Username, &user.Bio, &user.PublicKey, &createdAtStr); err != nil {
			log.Printf("Error scanning user row: %v", err)
			continue
		}

		// Parse UUID from string
		user.ID, err = uuid.Parse(idStr)
		if err != nil {
			log.Printf("Error parsing user ID: %v", err)
			continue
		}

		user.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			log.Printf("Error parsing created_at for user %s: %v", user.Username, err)
			continue
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through user rows: %w", err)
	}
	return users, nil
}

// AddMessage inserts a new encrypted message into the database.
func (d *DB) AddMessage(msg *models.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stmt, err := d.Prepare("INSERT INTO messages(sender_id, receiver_id, content, iv) VALUES(?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement for adding message: %w", err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(msg.SenderID, msg.ReceiverID, msg.Content, msg.IV)
	if err != nil {
		return fmt.Errorf("failed to execute statement for adding message: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID for message: %w", err)
	}
	msg.ID = uuid.MustParse(fmt.Sprintf("%d", id))
	log.Printf("Added message from %d to %d (ID: %d)", msg.SenderID, msg.ReceiverID, msg.ID)
	return nil
}

// GetMessagesBetweenUsers retrieves encrypted messages exchanged between two users.
// Messages are ordered by timestamp.
func (d *DB) GetMessagesBetweenUsers(user1ID, user2ID uuid.UUID) ([]*models.Message, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Select messages where sender is user1 and receiver is user2, OR sender is user2 and receiver is user1.
	rows, err := d.Query(`
		SELECT id, sender_id, receiver_id, content, iv, timestamp
		FROM messages
		WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
		ORDER BY timestamp ASC`,
		user1ID, user2ID, user2ID, user1ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages between users: %w", err)
	}
	defer rows.Close()

	var messages []*models.Message
	for rows.Next() {
		msg := models.Message{}
		var timestampStr string
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.ReceiverID, &msg.Content, &msg.IV, &timestampStr); err != nil {
			log.Printf("Error scanning message row: %v", err)
			continue
		}
		msg.Timestamp, err = time.Parse(time.RFC3339, timestampStr)
		if err != nil {
			log.Printf("Error parsing timestamp for message %d: %v", msg.ID, err)
			continue
		}
		messages = append(messages, &msg)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through message rows: %w", err)
	}
	return messages, nil
}

// AddFile inserts a new encrypted file metadata into the database.
func (d *DB) AddFile(file *models.File) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	stmt, err := d.Prepare("INSERT INTO files(sender_id, receiver_id, original_filename, file_path, iv) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement for adding file: %w", err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(file.SenderID, file.ReceiverID, file.OriginalFilename, file.FilePath, file.IV)
	if err != nil {
		return fmt.Errorf("failed to execute statement for adding file: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID for file: %w", err)
	}
	file.ID = uuid.MustParse(fmt.Sprintf("%d", id))
	log.Printf("Added file: %s from %d to %d (ID: %d)", file.OriginalFilename, file.SenderID, file.ReceiverID, file.ID)
	return nil
}

// GetFileMetadata retrieves file metadata by file ID.
func (d *DB) GetFileMetadata(fileID uuid.UUID) (*models.File, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.QueryRow("SELECT id, sender_id, receiver_id, original_filename, file_path, iv, timestamp FROM files WHERE id = ?", fileID)
	file := &models.File{}
	var timestampStr string
	err := row.Scan(&file.ID, &file.SenderID, &file.ReceiverID, &file.OriginalFilename, &file.FilePath, &file.IV, &timestampStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan file metadata: %w", err)
	}
	file.Timestamp, err = time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp for file: %w", err)
	}
	return file, nil
}

// AddMetric inserts a new non-identifiable metric entry.
func (d *DB) AddMetric(eventType string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Generate UUID for the metric
	metricID := uuid.New()

	stmt, err := d.Prepare("INSERT INTO metrics(id, event_type) VALUES(?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement for adding metric: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(metricID.String(), eventType)
	if err != nil {
		return fmt.Errorf("failed to execute statement for adding metric: %w", err)
	}
	log.Printf("Logged metric: %s with ID: %s", eventType, metricID.String())
	return nil
}
