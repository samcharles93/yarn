package session

import (
	"context"
)

type contextKey string

const sessionKey contextKey = "session"

// WithSession adds a session to the context
func WithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

// FromContext retrieves a session from the context
func FromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionKey).(*Session)
	return session, ok
}
