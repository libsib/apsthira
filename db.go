package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type Resume struct {
	ID               int64
	UserID           int64
	Slug             string
	R2Key            string
	OriginalFilename string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

type DB struct {
	conn   *sql.DB
	driver string
}

func InitDB(connStr string) (*DB, error) {
	var driver string
	var conn *sql.DB
	var err error

	// Detect driver based on connection string prefix
	if strings.HasPrefix(connStr, "postgres://") || strings.HasPrefix(connStr, "postgresql://") {
		driver = "postgres"
		conn, err = sql.Open("postgres", connStr)
	} else {
		driver = "sqlite3"
		conn, err = sql.Open("sqlite3", connStr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	db := &DB{conn: conn, driver: driver}

	// Create tables depending on database driver
	var query string
	if driver == "postgres" {
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS resumes (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			slug VARCHAR(255) UNIQUE NOT NULL,
			r2_key VARCHAR(255) NOT NULL,
			original_filename VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS sessions (
			token VARCHAR(255) PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_resumes_slug ON resumes(slug);
		CREATE INDEX IF NOT EXISTS idx_resumes_user_id ON resumes(user_id);
		`
	} else {
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS resumes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			r2_key TEXT NOT NULL,
			original_filename TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);

		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);

		CREATE INDEX IF NOT EXISTS idx_resumes_slug ON resumes(slug);
		CREATE INDEX IF NOT EXISTS idx_resumes_user_id ON resumes(user_id);
		`
	}

	if _, err := conn.Exec(query); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// q replaces placeholder '?' with '$1, $2...' for PostgreSQL
func (db *DB) q(query string) string {
	if db.driver == "postgres" {
		n := 1
		for {
			if !strings.Contains(query, "?") {
				break
			}
			query = strings.Replace(query, "?", fmt.Sprintf("$%d", n), 1)
			n++
		}
	}
	return query
}

// User Helpers
func (db *DB) CreateUser(username, passwordHash string) (int64, error) {
	now := time.Now()
	if db.driver == "postgres" {
		query := `INSERT INTO users (username, password_hash, created_at) VALUES ($1, $2, $3) RETURNING id`
		var id int64
		err := db.conn.QueryRow(query, username, passwordHash, now).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("failed to create user: %w", err)
		}
		return id, nil
	} else {
		query := `INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`
		res, err := db.conn.Exec(query, username, passwordHash, now)
		if err != nil {
			return 0, fmt.Errorf("failed to create user: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return 0, err
		}
		return id, nil
	}
}

func (db *DB) GetUserByUsername(username string) (*User, error) {
	query := db.q(`SELECT id, username, password_hash, created_at FROM users WHERE username = ?`)
	row := db.conn.QueryRow(query, username)
	var u User
	var createdAtStr string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &createdAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	// Parse timestamps
	u.CreatedAt = db.parseTime(createdAtStr)
	return &u, nil
}

func (db *DB) GetUserByID(id int64) (*User, error) {
	query := db.q(`SELECT id, username, password_hash, created_at FROM users WHERE id = ?`)
	row := db.conn.QueryRow(query, id)
	var u User
	var createdAtStr string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &createdAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	u.CreatedAt = db.parseTime(createdAtStr)
	return &u, nil
}

// Session Helpers
func (db *DB) CreateSession(token string, userID int64, expiresAt time.Time) error {
	query := db.q(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`)
	_, err := db.conn.Exec(query, token, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (db *DB) GetSession(token string) (*Session, error) {
	query := db.q(`SELECT token, user_id, expires_at FROM sessions WHERE token = ?`)
	row := db.conn.QueryRow(query, token)
	var s Session
	var expiresAtStr string
	err := row.Scan(&s.Token, &s.UserID, &expiresAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	s.ExpiresAt = db.parseTime(expiresAtStr)
	return &s, nil
}

func (db *DB) DeleteSession(token string) error {
	query := db.q(`DELETE FROM sessions WHERE token = ?`)
	_, err := db.conn.Exec(query, token)
	return err
}

// Resume Helpers
func (db *DB) CreateResume(userID int64, slug, r2Key, originalFilename string) error {
	query := db.q(`
	INSERT INTO resumes (user_id, slug, r2_key, original_filename, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?)
	`)
	now := time.Now()
	_, err := db.conn.Exec(query, userID, slug, r2Key, originalFilename, now, now)
	if err != nil {
		return fmt.Errorf("failed to insert resume record: %w", err)
	}
	return nil
}

func (db *DB) GetResume(slug string) (*Resume, error) {
	query := db.q(`
	SELECT id, user_id, slug, r2_key, original_filename, created_at, updated_at
	FROM resumes
	WHERE slug = ?
	`)
	row := db.conn.QueryRow(query, slug)
	var r Resume
	var createdAtStr, updatedAtStr string
	err := row.Scan(&r.ID, &r.UserID, &r.Slug, &r.R2Key, &r.OriginalFilename, &createdAtStr, &updatedAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to query resume: %w", err)
	}

	r.CreatedAt = db.parseTime(createdAtStr)
	r.UpdatedAt = db.parseTime(updatedAtStr)

	return &r, nil
}

func (db *DB) GetResumesByUserID(userID int64) ([]Resume, error) {
	query := db.q(`
	SELECT id, user_id, slug, r2_key, original_filename, created_at, updated_at
	FROM resumes
	WHERE user_id = ?
	ORDER BY updated_at DESC
	`)
	rows, err := db.conn.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Resume
	for rows.Next() {
		var r Resume
		var createdAtStr, updatedAtStr string
		err := rows.Scan(&r.ID, &r.UserID, &r.Slug, &r.R2Key, &r.OriginalFilename, &createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, err
		}
		r.CreatedAt = db.parseTime(createdAtStr)
		r.UpdatedAt = db.parseTime(updatedAtStr)
		list = append(list, r)
	}
	return list, nil
}

func (db *DB) UpdateResume(slug, r2Key, originalFilename string) error {
	query := db.q(`
	UPDATE resumes
	SET r2_key = ?, original_filename = ?, updated_at = ?
	WHERE slug = ?
	`)
	_, err := db.conn.Exec(query, r2Key, originalFilename, time.Now(), slug)
	if err != nil {
		return fmt.Errorf("failed to update resume record: %w", err)
	}
	return nil
}

func (db *DB) DeleteResume(slug string) error {
	query := db.q(`DELETE FROM resumes WHERE slug = ?`)
	_, err := db.conn.Exec(query, slug)
	return err
}

func (db *DB) DeleteUserAndResources(userID int64) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Delete all resumes associated with the user
	queryResumes := db.q(`DELETE FROM resumes WHERE user_id = ?`)
	_, err = tx.Exec(queryResumes, userID)
	if err != nil {
		return err
	}

	// 2. Delete all sessions associated with the user
	querySessions := db.q(`DELETE FROM sessions WHERE user_id = ?`)
	_, err = tx.Exec(querySessions, userID)
	if err != nil {
		return err
	}

	// 3. Delete the user
	queryUser := db.q(`DELETE FROM users WHERE id = ?`)
	_, err = tx.Exec(queryUser, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// parseTime formats datetime string from SQLite or PostgreSQL driver formats safely
func (db *DB) parseTime(tStr string) time.Time {
	// Truncate timezone info if sent as standard SQL datetime string format
	t, err := time.Parse(time.RFC3339, tStr)
	if err == nil {
		return t
	}
	
	// Fallback layouts
	layouts := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
	}
	for _, layout := range layouts {
		if val, err := time.Parse(layout, tStr); err == nil {
			return val
		}
	}
	return time.Now() // default fallback
}
