package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/internal/models"
)

// Session represents a user session
type Session struct {
	ID       string
	UserID   uuid.UUID
	Username string
	User     *models.User
	Created  time.Time
	LastSeen time.Time
}

// Manager manages user sessions
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewManager creates a new session manager
func NewManager() *Manager {
	manager := &Manager{
		sessions: make(map[string]*Session),
	}

	// Start cleanup goroutine
	go manager.cleanup()

	return manager
}

// CreateSession creates a new session for a user
func (m *Manager) CreateSession(user *models.User) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate secure session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:       sessionID,
		UserID:   user.ID,
		Username: user.Username,
		User:     user,
		Created:  time.Now(),
		LastSeen: time.Now(),
	}

	m.sessions[sessionID] = session
	return session, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	if exists {
		// Update last seen time
		session.LastSeen = time.Now()
	}
	return session, exists
}

// DeleteSession removes a session
func (m *Manager) DeleteSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
}

// GetSessionFromRequest extracts session from HTTP request
func (m *Manager) GetSessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, false
	}

	return m.GetSession(cookie.Value)
}

// SetSessionCookie sets session cookie on response
func (m *Manager) SetSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   24 * 60 * 60, // 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears session cookie
func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// cleanup removes expired sessions
func (m *Manager) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for sessionID, session := range m.sessions {
			// Remove sessions older than 24 hours
			if now.Sub(session.LastSeen) > 24*time.Hour {
				delete(m.sessions, sessionID)
			}
		}
		m.mu.Unlock()
	}
}

// generateSessionID generates a cryptographically secure session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// RequireAuth middleware that requires authentication
func (m *Manager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, exists := m.GetSessionFromRequest(r)
		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add session to request context for handlers to use
		r = r.WithContext(WithSession(r.Context(), session))
		next(w, r)
	}
}

// OptionalAuth middleware that optionally provides authentication
func (m *Manager) OptionalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, exists := m.GetSessionFromRequest(r)
		if exists {
			r = r.WithContext(WithSession(r.Context(), session))
		}
		next(w, r)
	}
}
