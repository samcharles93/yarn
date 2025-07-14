package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/samcharles93/yarn/internal/models"
)

// UploadFileHandler handles uploading encrypted files.
// It expects sender_id, receiver_id, original_filename, and the encrypted file content.
func (h *Handler) UploadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form data, max 10MB file size.
	err := r.ParseMultipartForm(10 << 20) // 10 MB
	if err != nil {
		http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	senderIDStr := r.FormValue("senderId")
	receiverIDStr := r.FormValue("receiverId")
	originalFilename := r.FormValue("originalFilename")
	ivBase64 := r.FormValue("iv") // IV sent as base64 string

	senderID, err := uuid.Parse(senderIDStr)
	if err != nil {
		http.Error(w, "Invalid senderId format", http.StatusBadRequest)
		return
	}
	receiverID, err := uuid.Parse(receiverIDStr)
	if err != nil {
		http.Error(w, "Invalid receiverId format", http.StatusBadRequest)
		return
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		http.Error(w, "Invalid IV format", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("encryptedFile")
	if err != nil {
		http.Error(w, "Failed to get encrypted file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a directory for uploaded files if it doesn't exist.
	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Printf("Failed to create upload directory: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate a unique filename for the encrypted file on the server.
	// This filename does not need to be human-readable as it's encrypted.
	serverFilename := fmt.Sprintf("%d_%s_%s", senderID, receiverID, handler.Filename) // Simple unique name
	filePath := filepath.Join(uploadDir, serverFilename)

	// Create the file on the server.
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("Failed to create file on server: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the encrypted file content from the request to the server file.
	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Failed to save encrypted file content: %v", err)
		http.Error(w, "Failed to save file content", http.StatusInternalServerError)
		return
	}

	// Store file metadata in the database.
	fileModel := &models.File{
		SenderID:         senderID,
		ReceiverID:       receiverID,
		OriginalFilename: originalFilename,
		FilePath:         filePath,
		IV:               iv,
	}

	if err := h.db.AddFile(fileModel); err != nil {
		log.Printf("Failed to add file metadata to database: %v", err)
		// Consider cleaning up the partially uploaded file if DB insertion fails.
		http.Error(w, "Failed to record file metadata", http.StatusInternalServerError)
		return
	}

	// Log metrics for file upload.
	h.db.AddMetric("file_uploaded")

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "File uploaded successfully",
		"fileId":   fileModel.ID,
		"filename": fileModel.OriginalFilename,
	})
}

// DownloadFileHandler handles downloading encrypted files.
// It expects file_id as a query parameter.
func (h *Handler) DownloadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileIDStr := r.URL.Query().Get("fileId")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid fileId", http.StatusBadRequest)
		return
	}

	fileMetadata, err := h.db.GetFileMetadata(fileID)
	if err != nil {
		log.Printf("Failed to get file metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if fileMetadata == nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Read the encrypted file content from disk.
	encryptedFileContent, err := os.ReadFile(fileMetadata.FilePath)
	if err != nil {
		log.Printf("Failed to read encrypted file from disk: %v", err)
		http.Error(w, "Failed to retrieve file content", http.StatusInternalServerError)
		return
	}

	// Prepare response with encrypted content and IV.
	response := map[string]string{
		"encryptedFileContent": base64.StdEncoding.EncodeToString(encryptedFileContent),
		"iv":                   base64.StdEncoding.EncodeToString(fileMetadata.IV),
		"originalFilename":     fileMetadata.OriginalFilename,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log metrics for file download.
	h.db.AddMetric("file_downloaded")
}
