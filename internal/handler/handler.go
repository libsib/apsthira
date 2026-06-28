package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"apsthira/internal/db"
	"apsthira/internal/storage"

	"github.com/exvillager/nanoserve"
)

type Handler struct {
	DB   *db.DB
	R2   *storage.R2Client
	Tmpl *template.Template
}

func New(database *db.DB, r2 *storage.R2Client, tmpl *template.Template) *Handler {
	return &Handler{DB: database, R2: r2, Tmpl: tmpl}
}

func (h *Handler) writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *Handler) generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSlug() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) getLoggedInUser(r *http.Request) *db.User {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil
	}
	user, session, err := h.DB.GetSessionWithUser(cookie.Value)
	if err != nil || user == nil || session == nil {
		return nil
	}
	if session.ExpiresAt.Before(time.Now()) {
		_ = h.DB.DeleteSession(session.Token)
		return nil
	}
	return user
}

// LoadUser attempts to load the logged-in user and stores it in context.
func (h *Handler) LoadUser(c *nanoserve.Context) error {
	user := h.getLoggedInUser(c.Request)
	if user != nil {
		c.Set("user", user)
	}
	return c.Next()
}

// RequireAuth enforces that a user is logged in.
// It redirects GET requests to /login, and returns 401 JSON for other HTTP methods.
func (h *Handler) RequireAuth(c *nanoserve.Context) error {
	user := h.getLoggedInUser(c.Request)
	if user == nil {
		if c.Request.Method == http.MethodGet {
			c.Redirect("/login", http.StatusSeeOther)
		} else {
			h.writeJSONError(c.Writer, http.StatusUnauthorized, "Unauthorized. Please log in.")
		}
		c.Abort()
		return nil
	}
	c.Set("user", user)
	return c.Next()
}

// mustGetUser retrieves the authenticated user from the context.
func (h *Handler) mustGetUser(c *nanoserve.Context) *db.User {
	val := c.Get("user")
	if val == nil {
		return nil
	}
	u, ok := val.(*db.User)
	if !ok {
		return nil
	}
	return u
}
