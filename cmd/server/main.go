package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/samcharles93/yarn/internal/database"
	"github.com/samcharles93/yarn/internal/handlers"
	"github.com/samcharles93/yarn/internal/websocket"
)

// tmpl holds the parsed HTML templates for the web UI.
var tmpl *template.Template

func main() {
	// Initialize the database connection.
	db, err := database.InitDB("yarn.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close() // Ensure the database connection is closed when the server exits.

	// Load HTML templates from the web/templates directory.
	// We parse all templates and store them in the tmpl variable.
	tmpl, err = template.ParseGlob(filepath.Join("web", "templates", "*.html"))
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	// Create websocket hub
	wsHub := websocket.NewHub(db)
	go wsHub.Run() // Start the hub in a goroutine

	// Create a new handlers.Handler instance, passing the database connection, templates, and websocket hub.
	h := handlers.NewHandler(db, tmpl, wsHub)

	// Serve static files (CSS, JavaScript) from the web/static directory.
	// This allows the browser to fetch stylesheets and scripts.
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("web", "static")))))

	// Register HTTP handlers for various routes.
	// The root path serves the main chat page.
	http.HandleFunc("/", h.ChatPageHandler)
	// /register handles new user registration.
	http.HandleFunc("/register", h.RegisterUserHandler)
	// /login handles user login (basic for this example).
	http.HandleFunc("/login", h.LoginHandler)
	// /api/send handles sending encrypted chat messages.
	http.HandleFunc("/api/send", h.SendMessageHandler)
	// /api/messages handles fetching encrypted chat messages.
	http.HandleFunc("/api/messages", h.GetMessagesHandler)
	// /api/file/upload handles uploading encrypted files.
	http.HandleFunc("/api/file/upload", h.UploadFileHandler)
	// /api/file/download handles downloading encrypted files.
	http.HandleFunc("/api/file/download", h.DownloadFileHandler)
	// /api/users handles fetching user list
	http.HandleFunc("/api/users", h.GetUsersHandler)
	// /ws handles websocket connections
	http.HandleFunc("/ws", h.WebSocketHandler)

	// Start the HTTP server on port 8080.
	port := ":8080"
	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(port, nil)) // ListenAndServe blocks until the server stops.
}
