package main

import (
	"log"
	"net/http"
	"path/filepath"

	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/handlers"
	"github.com/samcharles93/yarn/internal/websocket"
)

func main() {
	// Initialize the database connection
	db, err := database.InitDB("yarn.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create websocket hub
	wsHub := websocket.NewHub(db)
	go wsHub.Run()

	// Create handler with session management
	h := handlers.NewHandler(db, nil, wsHub)

	// Serve static files from the UI directory
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("UI", "static")))))

	// Modern HTMX+Templ UI routes
	http.HandleFunc("/", h.SimpleUIHandler)
	http.HandleFunc("/api/register", h.SimpleAPIRegisterHandler)
	http.HandleFunc("/api/login", h.SimpleAPILoginHandler)
	http.HandleFunc("/api/logout", h.SimpleAPILogoutHandler)
	http.HandleFunc("/api/chat/", h.SimpleAPIChatHandler)

	// WebSocket routes (HTMX)
	http.HandleFunc("/ws", h.WebSocketHandler)
	http.HandleFunc("/ws/htmx", h.HTMXWebSocketHandler)

	// Legacy API routes (for backward compatibility with any existing clients)
	http.HandleFunc("/api/send", h.SendMessageHandler)
	http.HandleFunc("/api/messages", h.GetMessagesHandler)
	http.HandleFunc("/api/file/upload", h.UploadFileHandler)
	http.HandleFunc("/api/file/download", h.DownloadFileHandler)
	http.HandleFunc("/api/users", h.GetUsersHandler)

	port := ":8080"
	log.Printf("🚀 Yarn E2EE Chat Server starting on port %s", port)
	log.Printf("📱 UI available at: http://localhost%s", port)
	log.Printf("🔌 WebSocket endpoints:")
	log.Printf("   - HTMX: ws://localhost%s/ws/htmx", port)

	log.Fatal(http.ListenAndServe(port, nil))
}
