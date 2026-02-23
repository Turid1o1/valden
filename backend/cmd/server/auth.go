package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

type authUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type authRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authTokensResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresAt    string   `json:"expires_at"`
	User         authUser `json:"user"`
}

type createBootstrapTokenRequest struct {
	Platform   string `json:"platform"`
	DeviceName string `json:"device_name"`
}

type createBootstrapTokenResponse struct {
	BootstrapToken string `json:"bootstrap_token"`
	ExpiresAt      string `json:"expires_at"`
	Platform       string `json:"platform,omitempty"`
}

type consumeBootstrapTokenRequest struct {
	BootstrapToken string                 `json:"bootstrap_token"`
	DeviceKey      string                 `json:"device_key"`
	DeviceMeta     map[string]interface{} `json:"device_meta"`
	DeviceName     string                 `json:"device_name,omitempty"`
}

type consumeBootstrapTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	User         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Device struct {
		DeviceID    string `json:"device_id"`
		DeviceToken string `json:"device_token"`
		PublicID    string `json:"public_id"`
	} `json:"device"`
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	return emailPattern.MatchString(email)
}

func bearerTokenFromRequest(r *http.Request) string {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return ""
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (a *App) issueTokenPair(ctx context.Context, userID string) (string, string, time.Time, error) {
	accessToken, err := randomToken(40)
	if err != nil {
		return "", "", time.Time{}, err
	}
	refreshToken, err := randomToken(56)
	if err != nil {
		return "", "", time.Time{}, err
	}

	expiresAt := time.Now().UTC().Add(a.cfg.AccessTokenTTL)
	refreshExpiresAt := time.Now().UTC().Add(a.cfg.RefreshTokenTTL)
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO user_access_tokens (id, user_id, token_hash, expires_at, revoked)
VALUES ($1, $2, $3, $4, false)`,
		uuid.NewString(),
		userID,
		sha256Hex(accessToken),
		expiresAt,
	); err != nil {
		return "", "", time.Time{}, err
	}

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO user_refresh_tokens (id, user_id, token_hash, expires_at, revoked)
VALUES ($1, $2, $3, $4, false)`,
		uuid.NewString(),
		userID,
		sha256Hex(refreshToken),
		refreshExpiresAt,
	); err != nil {
		return "", "", time.Time{}, err
	}

	if _, err = tx.ExecContext(ctx, `UPDATE user_access_tokens SET revoked = true WHERE expires_at < now()`); err != nil {
		return "", "", time.Time{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE user_refresh_tokens SET revoked = true WHERE expires_at < now()`); err != nil {
		return "", "", time.Time{}, err
	}

	if err = tx.Commit(); err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, expiresAt, nil
}

func (a *App) authenticateOptional(ctx context.Context, accessToken string) (*authUser, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, nil
	}

	var user authUser
	err := a.db.QueryRowContext(
		ctx,
		`SELECT u.id, u.email
FROM user_access_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1
  AND t.revoked = false
  AND t.expires_at > now()`,
		sha256Hex(accessToken),
	).Scan(&user.ID, &user.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) authenticateRequired(ctx context.Context, accessToken string) (*authUser, error) {
	user, err := a.authenticateOptional(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("unauthorized")
	}
	return user, nil
}

func (a *App) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	var req authRegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}

	email := normalizeEmail(req.Email)
	if !validateEmail(email) {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid email"})
		return
	}
	if len(req.Password) < 8 {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "password must be at least 8 characters"})
		return
	}

	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	userID := uuid.NewString()
	_, err = a.db.ExecContext(
		r.Context(),
		`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`,
		userID,
		email,
		string(passwordHashBytes),
	)
	if err != nil {
		if isUniqueViolation(err) {
			respondJSON(w, http.StatusConflict, errorResponse{Error: "email already exists"})
			return
		}
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	accessToken, refreshToken, expiresAt, err := a.issueTokenPair(r.Context(), userID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, authTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: authUser{
			ID:    userID,
			Email: email,
		},
	})
}

func (a *App) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req authLoginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}

	email := normalizeEmail(req.Email)
	if !validateEmail(email) || strings.TrimSpace(req.Password) == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password are required"})
		return
	}

	var userID string
	var passwordHash string
	err := a.db.QueryRowContext(
		r.Context(),
		`SELECT id, password_hash FROM users WHERE lower(email) = $1`,
		email,
	).Scan(&userID, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	accessToken, refreshToken, expiresAt, err := a.issueTokenPair(r.Context(), userID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, authTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: authUser{
			ID:    userID,
			Email: email,
		},
	})
}

func (a *App) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req authRefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "refresh_token is required"})
		return
	}

	var tokenID string
	var userID string
	var userEmail string
	tx, err := a.db.BeginTx(r.Context(), &sql.TxOptions{})
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}
	defer tx.Rollback()

	err = tx.QueryRowContext(
		r.Context(),
		`SELECT t.id, u.id, u.email
FROM user_refresh_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1
  AND t.revoked = false
  AND t.expires_at > now()
FOR UPDATE`,
		sha256Hex(req.RefreshToken),
	).Scan(&tokenID, &userID, &userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid refresh_token"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	if _, err = tx.ExecContext(r.Context(), `UPDATE user_refresh_tokens SET revoked = true WHERE id = $1`, tokenID); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}
	if err = tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	accessToken, refreshToken, expiresAt, err := a.issueTokenPair(r.Context(), userID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, authTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: authUser{
			ID:    userID,
			Email: userEmail,
		},
	})
}

func (a *App) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	user, err := a.authenticateRequired(r.Context(), bearerTokenFromRequest(r))
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"id":    user.ID,
		"email": user.Email,
	})
}

func (a *App) handleCreateBootstrapToken(w http.ResponseWriter, r *http.Request) {
	user, err := a.authenticateRequired(r.Context(), bearerTokenFromRequest(r))
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	var req createBootstrapTokenRequest
	if r.ContentLength > 0 {
		if err = decodeJSON(r, &req); err != nil {
			respondErr(w, http.StatusBadRequest, err)
			return
		}
	}

	bootstrapToken, err := randomToken(48)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}
	platform := strings.TrimSpace(strings.ToLower(req.Platform))
	expiresAt := time.Now().UTC().Add(a.cfg.BootstrapTTL)
	if _, err = a.db.ExecContext(
		r.Context(),
		`INSERT INTO bootstrap_tokens (id, user_id, token_hash, platform, device_name, expires_at, used)
VALUES ($1, $2, $3, $4, $5, $6, false)`,
		uuid.NewString(),
		user.ID,
		sha256Hex(bootstrapToken),
		platform,
		strings.TrimSpace(req.DeviceName),
		expiresAt,
	); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, createBootstrapTokenResponse{
		BootstrapToken: bootstrapToken,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		Platform:       platform,
	})
}

func (a *App) handleConsumeBootstrapToken(w http.ResponseWriter, r *http.Request) {
	var req consumeBootstrapTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.BootstrapToken) == "" || strings.TrimSpace(req.DeviceKey) == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "bootstrap_token and device_key are required"})
		return
	}

	var userID string
	var userEmail string
	var savedDeviceName sql.NullString
	err := a.db.QueryRowContext(
		r.Context(),
		`UPDATE bootstrap_tokens bt
SET used = true,
    consumed_at = now()
FROM users u
WHERE bt.user_id = u.id
  AND bt.token_hash = $1
  AND bt.used = false
  AND bt.expires_at > now()
RETURNING u.id, u.email, bt.device_name`,
		sha256Hex(req.BootstrapToken),
	).Scan(&userID, &userEmail, &savedDeviceName)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid or expired bootstrap_token"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	registerReq := registerDeviceRequest{
		DeviceKey:  req.DeviceKey,
		DeviceMeta: req.DeviceMeta,
		DeviceName: strings.TrimSpace(req.DeviceName),
	}
	if registerReq.DeviceName == "" && savedDeviceName.Valid {
		registerReq.DeviceName = savedDeviceName.String
	}

	result, err := a.upsertDevice(r.Context(), registerReq, &authUser{ID: userID, Email: userEmail})
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	accessToken, refreshToken, expiresAt, err := a.issueTokenPair(r.Context(), userID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	response := consumeBootstrapTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}
	response.User.ID = userID
	response.User.Email = userEmail
	response.Device.DeviceID = result.DeviceID
	response.Device.DeviceToken = result.DeviceToken
	response.Device.PublicID = result.PublicID

	respondJSON(w, http.StatusOK, response)
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
