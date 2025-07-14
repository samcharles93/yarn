package handlers

import "net/http"

// ChatPageHandler serves the main chat application page.
func (h *Handler) ChatPageHandler(w http.ResponseWriter, r *http.Request) {
	// Render the index.html template.
	err := h.tmpl.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
