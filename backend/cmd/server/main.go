package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
)

const (
	statusRequested    = "REQUESTED"
	statusNotified     = "NOTIFIED"
	statusAccepted     = "ACCEPTED"
	statusConnecting   = "CONNECTING"
	statusConnected    = "CONNECTED"
	statusReconnecting = "RECONNECTING"
	statusFailed       = "FAILED"
	statusEnded        = "ENDED"
)

var allowedTransitions = map[string]map[string]struct{}{
	statusRequested: {
		statusNotified: {},
		statusFailed:   {},
		statusEnded:    {},
	},
	statusNotified: {
		statusAccepted: {},
		statusFailed:   {},
		statusEnded:    {},
	},
	statusAccepted: {
		statusConnecting: {},
		statusFailed:     {},
		statusEnded:      {},
	},
	statusConnecting: {
		statusConnected:    {},
		statusReconnecting: {},
		statusFailed:       {},
		statusEnded:        {},
	},
	statusConnected: {
		statusReconnecting: {},
		statusFailed:       {},
		statusEnded:        {},
	},
	statusReconnecting: {
		statusConnecting: {},
		statusConnected:  {},
		statusFailed:     {},
		statusEnded:      {},
	},
	statusFailed: {
		statusEnded: {},
	},
	statusEnded: {},
}

type Config struct {
	ListenAddr        string
	DatabaseURL       string
	MigrationsPath    string
	TurnSecret        string
	TurnRealm         string
	TurnURLList       []string
	CORSOrigins       []string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	BootstrapTTL      time.Duration
	SessionRequireOTP bool
	LogJSON           bool
	SessionTimeout    time.Duration
	ReconnectWindow   time.Duration
}

type App struct {
	db       *sql.DB
	cfg      Config
	logger   *log.Logger
	limiter  *RateLimiter
	upgrader websocket.Upgrader

	mu              sync.RWMutex
	agentByDevice   map[string]*wsClient
	sessionPeers    map[string]*sessionPeer
	pendingByConn   map[string]map[int64]*queuedMessage
	sessionRuntime  map[string]*sessionRuntime
	nextDeliverySeq atomic.Int64
}

type sessionRuntime struct {
	offerSeen  bool
	answerSeen bool
}

type sessionPeer struct {
	agent  *wsClient
	viewer *wsClient
}

type queuedMessage struct {
	msg       WSMessage
	sessionID string
	lastSent  time.Time
	attempts  int
}

type wsClient struct {
	conn      *websocket.Conn
	connID    string
	role      string
	deviceID  string
	sessionID string
	writeMu   sync.Mutex
	closed    atomic.Bool
}

type WSMessage struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Seq       int64           `json:"seq,omitempty"`
	Ack       int64           `json:"ack,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type RateLimiter struct {
	mu      sync.Mutex
	events  map[string][]time.Time
	cleanup time.Time
}

type registerDeviceRequest struct {
	DeviceKey  string                 `json:"device_key"`
	DeviceMeta map[string]interface{} `json:"device_meta"`
	DeviceName string                 `json:"device_name,omitempty"`
}

type registerDeviceResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	PublicID    string `json:"public_id,omitempty"`
}

type createOTPRequest struct {
	DeviceToken string `json:"device_token"`
}

type createOTPResponse struct {
	OTP       string `json:"otp"`
	ExpiresAt string `json:"expires_at"`
}

type requestSessionRequest struct {
	DeviceID          string `json:"device_id"`
	OTP               string `json:"otp"`
	RequesterDeviceID string `json:"requester_device_id,omitempty"`
	RequesterPlatform string `json:"requester_platform,omitempty"`
	RequesterEmail    string `json:"requester_email,omitempty"`
}

type requestSessionResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

type turnCredentialsRequest struct {
	DeviceToken string `json:"device_token"`
}

type turnSessionCredentialsRequest struct {
	SessionID string `json:"session_id"`
}

type turnCredentialsResponse struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	TTL      int64    `json:"ttl_seconds"`
	URLs     []string `json:"urls"`
}

type sessionNotifyPayload struct {
	SessionID               string `json:"session_id"`
	Status                  string `json:"status"`
	RequesterEmail          string `json:"requester_email,omitempty"`
	RequesterPlatform       string `json:"requester_platform,omitempty"`
	RequesterDeviceID       string `json:"requester_device_id,omitempty"`
	RequesterDevicePublicID string `json:"requester_device_public_id,omitempty"`
}

type viewerHelloPayload struct {
	SessionID string `json:"session_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	db, err := openDB(cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("db connection failed: %v", err)
	}
	defer db.Close()

	if err := runMigrations(context.Background(), db, cfg.MigrationsPath); err != nil {
		logger.Fatalf("migrations failed: %v", err)
	}

	app := &App{
		db:      db,
		cfg:     cfg,
		logger:  logger,
		limiter: NewRateLimiter(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool { return true },
		},
		agentByDevice:  make(map[string]*wsClient),
		sessionPeers:   make(map[string]*sessionPeer),
		pendingByConn:  make(map[string]map[int64]*queuedMessage),
		sessionRuntime: make(map[string]*sessionRuntime),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.presenceSweeper(ctx)
	go app.pendingRedeliveryLoop(ctx)

	router := mux.NewRouter()
	router.HandleFunc("/healthz", app.handleHealth).Methods(http.MethodGet)
	router.HandleFunc("/v1/auth/register", app.handleAuthRegister).Methods(http.MethodPost)
	router.HandleFunc("/v1/auth/login", app.handleAuthLogin).Methods(http.MethodPost)
	router.HandleFunc("/v1/auth/refresh", app.handleAuthRefresh).Methods(http.MethodPost)
	router.HandleFunc("/v1/auth/me", app.handleAuthMe).Methods(http.MethodGet)
	router.HandleFunc("/v1/client/bootstrap/create", app.handleCreateBootstrapToken).Methods(http.MethodPost)
	router.HandleFunc("/v1/client/bootstrap/consume", app.handleConsumeBootstrapToken).Methods(http.MethodPost)
	router.HandleFunc("/ws", app.handleWebSocket)
	router.HandleFunc("/v1/device/register", app.handleRegisterDevice).Methods(http.MethodPost)
	router.HandleFunc("/v1/device/otp", app.handleCreateOTP).Methods(http.MethodPost)
	router.HandleFunc("/v1/session/request", app.handleSessionRequest).Methods(http.MethodPost)
	router.HandleFunc("/v1/session/{session_id}", app.handleGetSession).Methods(http.MethodGet)
	router.HandleFunc("/v1/presence/{device_id}", app.handleGetPresence).Methods(http.MethodGet)
	router.HandleFunc("/v1/turn/credentials", app.handleTurnCredentials).Methods(http.MethodPost)
	router.HandleFunc("/v1/turn/credentials/session", app.handleTurnSessionCredentials).Methods(http.MethodPost)
	router.HandleFunc("/v1/diagnostics/session/{session_id}", app.handleSessionDiagnostics).Methods(http.MethodGet)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           withRequestLogging(logger, withCORS(cfg, router)),
		ReadHeaderTimeout: 15 * time.Second,
	}

	logger.Printf("server_start addr=%s", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("server stopped: %v", err)
	}
}

func loadConfig() Config {
	turnURLs := strings.Split(strings.TrimSpace(envOrDefault("TURN_URLS", "turn:localhost:3478?transport=udp,turns:localhost:5349?transport=tcp")), ",")
	result := make([]string, 0, len(turnURLs))
	for _, u := range turnURLs {
		u = strings.TrimSpace(u)
		if u != "" {
			result = append(result, u)
		}
	}
	if len(result) == 0 {
		result = []string{"turn:localhost:3478?transport=udp"}
	}
	corsOriginsRaw := strings.Split(strings.TrimSpace(envOrDefault("CORS_ALLOWED_ORIGINS", "*")), ",")
	corsOrigins := make([]string, 0, len(corsOriginsRaw))
	for _, origin := range corsOriginsRaw {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			corsOrigins = append(corsOrigins, origin)
		}
	}
	if len(corsOrigins) == 0 {
		corsOrigins = []string{"*"}
	}
	sessionRequireOTP := strings.EqualFold(strings.TrimSpace(envOrDefault("SESSION_REQUIRE_OTP", "true")), "true")

	return Config{
		ListenAddr:        envOrDefault("LISTEN_ADDR", ":8080"),
		DatabaseURL:       envOrDefault("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/valden?sslmode=disable"),
		MigrationsPath:    envOrDefault("MIGRATIONS_PATH", "/app/migrations"),
		TurnSecret:        envOrDefault("TURN_SECRET", "change-me-turn-secret"),
		TurnRealm:         envOrDefault("TURN_REALM", "valden.local"),
		TurnURLList:       result,
		CORSOrigins:       corsOrigins,
		AccessTokenTTL:    20 * time.Minute,
		RefreshTokenTTL:   30 * 24 * time.Hour,
		BootstrapTTL:      20 * time.Minute,
		SessionRequireOTP: sessionRequireOTP,
		SessionTimeout:    10 * time.Second,
		ReconnectWindow:   45 * time.Second,
	}
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 30; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			return db, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("ping database: %w", err)
}

func runMigrations(ctx context.Context, db *sql.DB, migrationsPath string) error {
	entries, err := os.ReadDir(migrationsPath)
	if err != nil {
		return err
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, filepath.Join(migrationsPath, e.Name()))
	}
	sort.Strings(files)

	for _, file := range files {
		sqlBytes, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("migration %s: %w", file, err)
		}
	}
	return nil
}

func withRequestLogging(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("http method=%s path=%s ip=%s elapsed_ms=%d", r.Method, r.URL.Path, clientIP(r), time.Since(start).Milliseconds())
	})
}

func withCORS(cfg Config, next http.Handler) http.Handler {
	allowAll := false
	allowed := make(map[string]struct{}, len(cfg.CORSOrigins))
	for _, origin := range cfg.CORSOrigins {
		if origin == "*" {
			allowAll = true
			continue
		}
		allowed[origin] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else if _, ok := allowed[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req registerDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.DeviceKey) == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_key is required"})
		return
	}
	user, _ := a.authenticateOptional(r.Context(), bearerTokenFromRequest(r))
	result, err := a.upsertDevice(r.Context(), req, user)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, registerDeviceResponse{
		DeviceID:    result.DeviceID,
		DeviceToken: result.DeviceToken,
		PublicID:    result.PublicID,
	})
}

func (a *App) handleCreateOTP(w http.ResponseWriter, r *http.Request) {
	var req createOTPRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if req.DeviceToken == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_token is required"})
		return
	}

	ip := clientIP(r)
	if !a.limiter.Allow("otp_ip:"+ip, 20, 5*time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded for ip"})
		return
	}

	var deviceID string
	err := a.db.QueryRowContext(r.Context(), `SELECT id FROM devices WHERE token_hash = $1`, sha256Hex(req.DeviceToken)).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid device_token"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	if !a.limiter.Allow("otp_device:"+deviceID, 5, 5*time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded for device"})
		return
	}

	otpCode, err := randomOTP()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	var expiresAt time.Time
	err = a.db.QueryRowContext(
		r.Context(),
		`INSERT INTO otp (id, device_id, otp_hash, expires_at, attempts_remaining, used)
VALUES ($1, $2, $3, now() + interval '90 seconds', 5, false)
RETURNING expires_at`,
		uuid.NewString(),
		deviceID,
		sha256Hex(otpCode),
	).Scan(&expiresAt)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, createOTPResponse{
		OTP:       otpCode,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

func (a *App) handleSessionRequest(w http.ResponseWriter, r *http.Request) {
	var req requestSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if req.DeviceID == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_id is required"})
		return
	}

	targetDeviceID, err := a.resolveDeviceIdentifier(r.Context(), req.DeviceID)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "target device not found"})
		return
	}

	var requesterUserID interface{}
	requesterEmail := strings.TrimSpace(req.RequesterEmail)
	if requesterEmail != "" {
		requesterEmail = normalizeEmail(requesterEmail)
		if !validateEmail(requesterEmail) {
			requesterEmail = ""
		}
	}
	if user, authErr := a.authenticateOptional(r.Context(), bearerTokenFromRequest(r)); authErr == nil && user != nil {
		requesterUserID = user.ID
		requesterEmail = user.Email
	}

	requesterPlatform := strings.TrimSpace(req.RequesterPlatform)
	if len(requesterPlatform) > 120 {
		requesterPlatform = requesterPlatform[:120]
	}

	var requesterDeviceIDValue interface{}
	requesterDeviceID := ""
	requesterDevicePublicID := ""
	if rawRequesterDeviceID := strings.TrimSpace(req.RequesterDeviceID); rawRequesterDeviceID != "" {
		if resolvedRequesterDeviceID, resolveErr := a.resolveDeviceIdentifier(r.Context(), rawRequesterDeviceID); resolveErr == nil {
			requesterDeviceIDValue = resolvedRequesterDeviceID
			requesterDeviceID = resolvedRequesterDeviceID
			var publicID sql.NullString
			if err := a.db.QueryRowContext(
				r.Context(),
				`SELECT public_id FROM devices WHERE id = $1`,
				resolvedRequesterDeviceID,
			).Scan(&publicID); err == nil && publicID.Valid {
				requesterDevicePublicID = strings.TrimSpace(publicID.String)
			}
		}
	}

	ip := clientIP(r)
	if !a.cfg.SessionRequireOTP {
		sessionID := uuid.NewString()
		tx, txErr := a.db.BeginTx(r.Context(), &sql.TxOptions{})
		if txErr != nil {
			respondErr(w, http.StatusInternalServerError, txErr)
			return
		}
		defer tx.Rollback()

		if _, txErr = tx.ExecContext(
			r.Context(),
			`INSERT INTO sessions (id, agent_device_id, viewer_device_id, status, requester_user_id, requester_email, requester_platform)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			sessionID,
			targetDeviceID,
			requesterDeviceIDValue,
			statusRequested,
			requesterUserID,
			requesterEmail,
			requesterPlatform,
		); txErr != nil {
			respondErr(w, http.StatusInternalServerError, txErr)
			return
		}

		requestPayload := map[string]interface{}{
			"ip": ip,
		}
		if requesterEmail != "" {
			requestPayload["requester_email"] = requesterEmail
		}
		if requesterPlatform != "" {
			requestPayload["requester_platform"] = requesterPlatform
		}
		if requesterDeviceID != "" {
			requestPayload["requester_device_id"] = requesterDeviceID
		}
		if requesterDevicePublicID != "" {
			requestPayload["requester_device_public_id"] = requesterDevicePublicID
		}
		if txErr = insertEventWithTx(r.Context(), tx, sessionID, "", statusRequested, "session_requested_no_otp", requestPayload); txErr != nil {
			respondErr(w, http.StatusInternalServerError, txErr)
			return
		}
		if txErr = tx.Commit(); txErr != nil {
			respondErr(w, http.StatusInternalServerError, txErr)
			return
		}

		a.notifyAgentIfOnline(r.Context(), sessionID, targetDeviceID)

		respondJSON(w, http.StatusOK, requestSessionResponse{
			SessionID: sessionID,
			Status:    statusRequested,
		})
		return
	}
	if req.OTP == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "otp is required"})
		return
	}

	if !a.limiter.Allow("otp_try_ip:"+ip, 5, 5*time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many otp attempts for ip"})
		return
	}
	if !a.limiter.Allow("otp_try_device:"+targetDeviceID, 5, 5*time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many otp attempts for device"})
		return
	}

	tx, err := a.db.BeginTx(r.Context(), &sql.TxOptions{})
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}
	defer tx.Rollback()

	var otpID string
	var otpHash string
	var attemptsRemaining int
	var expiresAt time.Time
	err = tx.QueryRowContext(
		r.Context(),
		`SELECT id, otp_hash, attempts_remaining, expires_at
FROM otp
WHERE device_id = $1
  AND used = false
  AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE`,
		targetDeviceID,
	).Scan(&otpID, &otpHash, &attemptsRemaining, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "otp not found or expired"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	if attemptsRemaining <= 0 {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "otp attempts exceeded"})
		return
	}

	if !constantTimeEquals(otpHash, sha256Hex(req.OTP)) {
		if _, err := tx.ExecContext(r.Context(), `UPDATE otp SET attempts_remaining = GREATEST(attempts_remaining - 1, 0) WHERE id = $1`, otpID); err != nil {
			respondErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := tx.Commit(); err != nil {
			respondErr(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid otp"})
		return
	}

	if _, err := tx.ExecContext(r.Context(), `UPDATE otp SET used = true WHERE id = $1`, otpID); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	sessionID := uuid.NewString()
	if _, err := tx.ExecContext(
		r.Context(),
		`INSERT INTO sessions (id, agent_device_id, viewer_device_id, status, requester_user_id, requester_email, requester_platform)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sessionID,
		targetDeviceID,
		requesterDeviceIDValue,
		statusRequested,
		requesterUserID,
		requesterEmail,
		requesterPlatform,
	); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	payload := map[string]interface{}{
		"ip":         ip,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}
	if requesterEmail != "" {
		payload["requester_email"] = requesterEmail
	}
	if requesterPlatform != "" {
		payload["requester_platform"] = requesterPlatform
	}
	if requesterDeviceID != "" {
		payload["requester_device_id"] = requesterDeviceID
	}
	if requesterDevicePublicID != "" {
		payload["requester_device_public_id"] = requesterDevicePublicID
	}
	if err := insertEventWithTx(r.Context(), tx, sessionID, "", statusRequested, "session_requested", payload); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	a.notifyAgentIfOnline(r.Context(), sessionID, targetDeviceID)

	respondJSON(w, http.StatusOK, requestSessionResponse{
		SessionID: sessionID,
		Status:    statusRequested,
	})
}

func (a *App) handleTurnCredentials(w http.ResponseWriter, r *http.Request) {
	var req turnCredentialsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if req.DeviceToken == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_token is required"})
		return
	}

	var deviceID string
	err := a.db.QueryRowContext(r.Context(), `SELECT id FROM devices WHERE token_hash = $1`, sha256Hex(req.DeviceToken)).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid device_token"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	ttlSeconds := int64(600)
	expiry := time.Now().UTC().Unix() + ttlSeconds
	username := fmt.Sprintf("%d:%s", expiry, deviceID)
	h := hmac.New(sha1.New, []byte(a.cfg.TurnSecret))
	h.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(h.Sum(nil))

	respondJSON(w, http.StatusOK, turnCredentialsResponse{
		Username: username,
		Password: password,
		TTL:      ttlSeconds,
		URLs:     a.cfg.TurnURLList,
	})
}

func (a *App) handleTurnSessionCredentials(w http.ResponseWriter, r *http.Request) {
	var req turnSessionCredentialsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondErr(w, http.StatusBadRequest, err)
		return
	}
	if req.SessionID == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "session_id is required"})
		return
	}

	var sessionID string
	err := a.db.QueryRowContext(
		r.Context(),
		`SELECT id
FROM sessions
WHERE id = $1
  AND created_at > now() - interval '30 minutes'`,
		req.SessionID,
	).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid or expired session_id"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	ttlSeconds := int64(600)
	expiry := time.Now().UTC().Unix() + ttlSeconds
	username := fmt.Sprintf("%d:session:%s", expiry, sessionID)
	h := hmac.New(sha1.New, []byte(a.cfg.TurnSecret))
	h.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(h.Sum(nil))

	respondJSON(w, http.StatusOK, turnCredentialsResponse{
		Username: username,
		Password: password,
		TTL:      ttlSeconds,
		URLs:     a.cfg.TurnURLList,
	})
}

func (a *App) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sessionID := mux.Vars(r)["session_id"]
	if sessionID == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "session_id is required"})
		return
	}

	var status string
	var transport sql.NullString
	var lastError sql.NullString
	var updatedAt time.Time
	err := a.db.QueryRowContext(
		r.Context(),
		`SELECT status, transport_mode, last_error, updated_at FROM sessions WHERE id = $1`,
		sessionID,
	).Scan(&status, &transport, &lastError, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusNotFound, errorResponse{Error: "session not found"})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"session_id":     sessionID,
		"status":         status,
		"transport_mode": transport.String,
		"last_error":     lastError.String,
		"updated_at":     updatedAt.UTC().Format(time.RFC3339),
	})
}

func (a *App) handleGetPresence(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]
	if deviceID == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_id is required"})
		return
	}
	resolvedDeviceID, err := a.resolveDeviceIdentifier(r.Context(), deviceID)
	if err != nil {
		resolvedDeviceID = deviceID
	}

	var online bool
	var lastSeen sql.NullTime
	err = a.db.QueryRowContext(
		r.Context(),
		`SELECT online, last_seen FROM presence WHERE device_id = $1`,
		resolvedDeviceID,
	).Scan(&online, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"device_id": deviceID,
			"online":    false,
			"last_seen": nil,
		})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}

	var lastSeenStr interface{}
	if lastSeen.Valid {
		lastSeenStr = lastSeen.Time.UTC().Format(time.RFC3339)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"online":    online,
		"last_seen": lastSeenStr,
	})
}

func (a *App) handleSessionDiagnostics(w http.ResponseWriter, r *http.Request) {
	sessionID := mux.Vars(r)["session_id"]
	rows, err := a.db.QueryContext(
		r.Context(),
		`SELECT id, from_state, to_state, reason, payload, created_at
FROM session_events
WHERE session_id = $1
ORDER BY created_at ASC`,
		sessionID,
	)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	events := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int64
		var fromState sql.NullString
		var toState sql.NullString
		var reason sql.NullString
		var payload []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &fromState, &toState, &reason, &payload, &createdAt); err != nil {
			respondErr(w, http.StatusInternalServerError, err)
			return
		}

		var payloadAny interface{}
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &payloadAny)
		}

		events = append(events, map[string]interface{}{
			"id":         id,
			"from_state": fromState.String,
			"to_state":   toState.String,
			"reason":     reason.String,
			"payload":    payloadAny,
			"created_at": createdAt.UTC().Format(time.RFC3339Nano),
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": sessionID,
		"events":     events,
	})
}

func (a *App) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	deviceToken := strings.TrimSpace(r.URL.Query().Get("device_token"))

	if role != "agent" && role != "viewer" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "role must be agent or viewer"})
		return
	}
	if deviceID == "" {
		respondJSON(w, http.StatusBadRequest, errorResponse{Error: "device_id is required"})
		return
	}

	if role == "agent" {
		ok, err := a.validateDeviceToken(r.Context(), deviceID, deviceToken)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			respondJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid device token"})
			return
		}
	}

	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		a.logger.Printf("ws upgrade failed: %v", err)
		return
	}

	client := &wsClient{
		conn:      conn,
		connID:    uuid.NewString(),
		role:      role,
		deviceID:  deviceID,
		sessionID: strings.TrimSpace(r.URL.Query().Get("session_id")),
	}

	a.registerClient(client)
	defer a.unregisterClient(client)

	if role == "agent" {
		a.updatePresence(context.Background(), client.deviceID, true)
	}

	_ = client.send(WSMessage{Type: "WS_READY", Payload: mustJSON(map[string]string{"role": role})})

	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				a.logger.Printf("ws read error conn=%s role=%s device=%s err=%v", client.connID, client.role, client.deviceID, err)
			}
			return
		}

		if msg.Ack != 0 {
			a.ackDelivery(client.connID, msg.Ack)
		}

		if msg.Type == "" {
			continue
		}
		if msg.Type == "PING" {
			_ = client.send(WSMessage{Type: "PONG", SessionID: msg.SessionID})
			if client.role == "agent" {
				a.updatePresence(context.Background(), client.deviceID, true)
			}
			continue
		}

		if err := a.handleWSMessage(context.Background(), client, msg); err != nil {
			a.logger.Printf("ws handle error conn=%s type=%s session=%s err=%v", client.connID, msg.Type, msg.SessionID, err)
			_ = client.send(WSMessage{
				Type:      "ERROR",
				SessionID: msg.SessionID,
				Payload:   mustJSON(map[string]string{"error": err.Error()}),
			})
		}
	}
}

func (a *App) handleWSMessage(ctx context.Context, sender *wsClient, msg WSMessage) error {
	sessionID := strings.TrimSpace(msg.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(sender.sessionID)
	}

	switch msg.Type {
	case "AGENT_ONLINE":
		if sender.role != "agent" {
			return errors.New("only agent can send AGENT_ONLINE")
		}
		a.updatePresence(ctx, sender.deviceID, true)
		return nil

	case "VIEWER_HELLO":
		if sender.role != "viewer" {
			return errors.New("only viewer can send VIEWER_HELLO")
		}
		if len(msg.Payload) > 0 {
			var payload viewerHelloPayload
			if err := json.Unmarshal(msg.Payload, &payload); err == nil && payload.SessionID != "" {
				sessionID = payload.SessionID
			}
		}
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		sender.sessionID = sessionID
		a.bindSessionPeer(sessionID, sender)

		if err := a.transitionSession(ctx, sessionID, statusNotified, "viewer_hello", map[string]string{"by": sender.role}); err != nil && !errors.Is(err, ErrInvalidTransition) {
			return err
		}

		agent := a.getSessionPeer(sessionID, "agent")
		if agent != nil {
			notifyPayload := a.getSessionNotifyPayload(ctx, sessionID, statusNotified)
			notify := WSMessage{
				Type:      "SESSION_NOTIFY",
				SessionID: sessionID,
				Payload:   mustJSON(notifyPayload),
			}
			_ = agent.send(notify)
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)

	case "SESSION_ACCEPT":
		if sender.role != "agent" {
			return errors.New("only agent can accept sessions")
		}
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		a.bindSessionPeer(sessionID, sender)
		if err := a.transitionSession(ctx, sessionID, statusAccepted, "agent_accept", map[string]string{"by": sender.deviceID}); err != nil {
			return err
		}
		return a.forwardToPeer(ctx, sender, msg, false)

	case "SDP_OFFER":
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		a.bindSessionPeer(sessionID, sender)
		if err := a.transitionSession(ctx, sessionID, statusConnecting, "sdp_offer", nil); err != nil {
			if !errors.Is(err, ErrInvalidTransition) {
				return err
			}
		}
		a.markOfferSeen(sessionID)
		if err := a.forwardToPeer(ctx, sender, msg, true); err != nil {
			return err
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)

	case "SDP_ANSWER":
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		a.bindSessionPeer(sessionID, sender)
		a.markAnswerSeen(sessionID)
		if a.hasOfferAndAnswer(sessionID) {
			if err := a.transitionSession(ctx, sessionID, statusConnected, "sdp_answer", nil); err != nil {
				if !errors.Is(err, ErrInvalidTransition) {
					return err
				}
			}
		}
		if err := a.forwardToPeer(ctx, sender, msg, true); err != nil {
			return err
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)

	case "ICE_RESTART":
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		if err := a.transitionSession(ctx, sessionID, statusReconnecting, "ice_restart", nil); err != nil {
			if !errors.Is(err, ErrInvalidTransition) {
				return err
			}
		}
		if err := a.forwardToPeer(ctx, sender, msg, true); err != nil {
			return err
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)

	case "HANGUP":
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		if err := a.transitionSession(ctx, sessionID, statusEnded, "hangup", nil); err != nil {
			if !errors.Is(err, ErrInvalidTransition) {
				return err
			}
		}
		if err := a.forwardToPeer(ctx, sender, msg, false); err != nil {
			return err
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)

	default:
		if sessionID == "" {
			return errors.New("session_id is required")
		}
		if err := a.forwardToPeer(ctx, sender, msg, false); err != nil {
			return err
		}
		return a.insertMessageEvent(ctx, sessionID, sender.role, msg)
	}
}

func (a *App) notifyAgentIfOnline(ctx context.Context, sessionID, deviceID string) {
	agent := a.getAgent(deviceID)
	if agent == nil {
		return
	}

	a.bindSessionPeer(sessionID, agent)
	if err := a.transitionSession(ctx, sessionID, statusNotified, "agent_online_notify", nil); err != nil {
		if !errors.Is(err, ErrInvalidTransition) {
			a.logger.Printf("notify transition failed session=%s err=%v", sessionID, err)
		}
	}

	notify := WSMessage{
		Type:      "SESSION_NOTIFY",
		SessionID: sessionID,
		Payload:   mustJSON(a.getSessionNotifyPayload(ctx, sessionID, statusNotified)),
	}
	if err := agent.send(notify); err != nil {
		a.logger.Printf("notify agent failed session=%s agent=%s err=%v", sessionID, agent.deviceID, err)
	}
}

func (a *App) getSessionNotifyPayload(ctx context.Context, sessionID, status string) sessionNotifyPayload {
	result := sessionNotifyPayload{
		SessionID: sessionID,
		Status:    status,
	}

	var requesterEmail sql.NullString
	var requesterPlatform sql.NullString
	var requesterDeviceID sql.NullString
	var requesterDevicePublicID sql.NullString
	err := a.db.QueryRowContext(
		ctx,
		`SELECT
    s.requester_email,
    s.requester_platform,
    CASE WHEN d.id IS NULL THEN NULL ELSE d.id::text END,
    d.public_id
FROM sessions s
LEFT JOIN devices d ON d.id = s.viewer_device_id
WHERE s.id = $1`,
		sessionID,
	).Scan(&requesterEmail, &requesterPlatform, &requesterDeviceID, &requesterDevicePublicID)
	if err != nil {
		return result
	}

	if requesterEmail.Valid {
		result.RequesterEmail = strings.TrimSpace(requesterEmail.String)
	}
	if requesterPlatform.Valid {
		result.RequesterPlatform = strings.TrimSpace(requesterPlatform.String)
	}
	if requesterDeviceID.Valid {
		result.RequesterDeviceID = strings.TrimSpace(requesterDeviceID.String)
	}
	if requesterDevicePublicID.Valid {
		result.RequesterDevicePublicID = strings.TrimSpace(requesterDevicePublicID.String)
	}

	return result
}

var ErrInvalidTransition = errors.New("invalid session transition")

func (a *App) transitionSession(ctx context.Context, sessionID, nextState, reason string, payload interface{}) error {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var currentState string
	err = tx.QueryRowContext(ctx, `SELECT status FROM sessions WHERE id = $1 FOR UPDATE`, sessionID).Scan(&currentState)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return err
	}

	if currentState == nextState {
		return nil
	}

	if _, ok := allowedTransitions[currentState][nextState]; !ok {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, currentState, nextState)
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE sessions
SET status = $2,
    updated_at = now(),
    last_error = CASE WHEN $2 = $3 THEN $4 ELSE last_error END
WHERE id = $1`,
		sessionID,
		nextState,
		statusFailed,
		reason,
	)
	if err != nil {
		return err
	}

	if err := insertEventWithTx(ctx, tx, sessionID, currentState, nextState, reason, payload); err != nil {
		return err
	}

	return tx.Commit()
}

func (a *App) registerClient(client *wsClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if client.role == "agent" {
		a.agentByDevice[client.deviceID] = client
	}
	if _, ok := a.pendingByConn[client.connID]; !ok {
		a.pendingByConn[client.connID] = make(map[int64]*queuedMessage)
	}
	if client.sessionID != "" {
		peer := a.ensureSessionPeerLocked(client.sessionID)
		if client.role == "agent" {
			peer.agent = client
		} else {
			peer.viewer = client
		}
	}
}

func (a *App) unregisterClient(client *wsClient) {
	client.closed.Store(true)
	_ = client.conn.Close()

	a.mu.Lock()
	if current, ok := a.agentByDevice[client.deviceID]; ok && current.connID == client.connID {
		delete(a.agentByDevice, client.deviceID)
	}
	delete(a.pendingByConn, client.connID)

	affectedSessions := make([]string, 0)
	for sessionID, peers := range a.sessionPeers {
		changed := false
		if peers.agent != nil && peers.agent.connID == client.connID {
			peers.agent = nil
			changed = true
		}
		if peers.viewer != nil && peers.viewer.connID == client.connID {
			peers.viewer = nil
			changed = true
		}
		if changed {
			affectedSessions = append(affectedSessions, sessionID)
		}
		if peers.agent == nil && peers.viewer == nil {
			delete(a.sessionPeers, sessionID)
			delete(a.sessionRuntime, sessionID)
		}
	}
	a.mu.Unlock()

	if client.role == "agent" {
		a.updatePresence(context.Background(), client.deviceID, false)
	}

	for _, sessionID := range affectedSessions {
		if err := a.transitionSession(context.Background(), sessionID, statusReconnecting, "peer_disconnected", map[string]string{"role": client.role}); err != nil {
			if !errors.Is(err, ErrInvalidTransition) {
				a.logger.Printf("reconnect transition failed session=%s err=%v", sessionID, err)
			}
		}
	}
}

func (a *App) bindSessionPeer(sessionID string, client *wsClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	peer := a.ensureSessionPeerLocked(sessionID)
	if client.role == "agent" {
		peer.agent = client
	} else {
		peer.viewer = client
	}
}

func (a *App) ensureSessionPeerLocked(sessionID string) *sessionPeer {
	peer, ok := a.sessionPeers[sessionID]
	if !ok {
		peer = &sessionPeer{}
		a.sessionPeers[sessionID] = peer
	}
	if _, ok := a.sessionRuntime[sessionID]; !ok {
		a.sessionRuntime[sessionID] = &sessionRuntime{}
	}
	return peer
}

func (a *App) getSessionPeer(sessionID, role string) *wsClient {
	a.mu.RLock()
	defer a.mu.RUnlock()
	peer := a.sessionPeers[sessionID]
	if peer == nil {
		return nil
	}
	if role == "agent" {
		return peer.agent
	}
	if role == "viewer" {
		return peer.viewer
	}
	return nil
}

func (a *App) getAgent(deviceID string) *wsClient {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.agentByDevice[deviceID]
}

func (a *App) markOfferSeen(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	runtime, ok := a.sessionRuntime[sessionID]
	if !ok {
		runtime = &sessionRuntime{}
		a.sessionRuntime[sessionID] = runtime
	}
	runtime.offerSeen = true
}

func (a *App) markAnswerSeen(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	runtime, ok := a.sessionRuntime[sessionID]
	if !ok {
		runtime = &sessionRuntime{}
		a.sessionRuntime[sessionID] = runtime
	}
	runtime.answerSeen = true
}

func (a *App) hasOfferAndAnswer(sessionID string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	runtime := a.sessionRuntime[sessionID]
	return runtime != nil && runtime.offerSeen && runtime.answerSeen
}

func (a *App) forwardToPeer(ctx context.Context, sender *wsClient, msg WSMessage, guaranteeDelivery bool) error {
	sessionID := strings.TrimSpace(msg.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(sender.sessionID)
	}
	if sessionID == "" {
		return errors.New("session_id is required")
	}

	var receiver *wsClient
	if sender.role == "agent" {
		receiver = a.getSessionPeer(sessionID, "viewer")
	} else {
		receiver = a.getSessionPeer(sessionID, "agent")
	}

	if receiver == nil {
		return errors.New("peer is not connected")
	}

	outbound := msg
	outbound.SessionID = sessionID

	if guaranteeDelivery {
		seq := a.nextDeliverySeq.Add(1)
		outbound.Seq = seq
		a.enqueuePending(receiver.connID, seq, outbound, sessionID)
	}

	if err := receiver.send(outbound); err != nil {
		if guaranteeDelivery {
			return nil
		}
		return err
	}

	if msg.Type == "ICE_CANDIDATE" {
		a.logger.Printf("ice_candidate session=%s from=%s", sessionID, sender.role)
	}
	if msg.Type == "SDP_OFFER" || msg.Type == "SDP_ANSWER" {
		a.logger.Printf("sdp_forward session=%s type=%s seq=%d", sessionID, msg.Type, outbound.Seq)
	}

	return a.insertMessageEvent(ctx, sessionID, sender.role, msg)
}

func (a *App) enqueuePending(connID string, seq int64, msg WSMessage, sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.pendingByConn[connID]; !ok {
		a.pendingByConn[connID] = make(map[int64]*queuedMessage)
	}
	a.pendingByConn[connID][seq] = &queuedMessage{
		msg:       msg,
		sessionID: sessionID,
		lastSent:  time.Now(),
		attempts:  1,
	}
}

func (a *App) ackDelivery(connID string, seq int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if messages, ok := a.pendingByConn[connID]; ok {
		delete(messages, seq)
	}
}

func (a *App) pendingRedeliveryLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.redeliverPending()
		}
	}
}

func (a *App) redeliverPending() {
	type resendItem struct {
		receiver *wsClient
		connID   string
		seq      int64
		msg      WSMessage
		attempts int
		session  string
	}

	items := make([]resendItem, 0)
	toDelete := make([]struct {
		connID string
		seq    int64
	}, 0)

	now := time.Now()
	a.mu.Lock()
	for sessionID, peers := range a.sessionPeers {
		_ = sessionID
		if peers.agent != nil {
			if queuedMap, ok := a.pendingByConn[peers.agent.connID]; ok {
				for seq, qm := range queuedMap {
					if now.Sub(qm.lastSent) < 2*time.Second {
						continue
					}
					if qm.attempts >= 10 {
						toDelete = append(toDelete, struct {
							connID string
							seq    int64
						}{connID: peers.agent.connID, seq: seq})
						continue
					}
					qm.attempts++
					qm.lastSent = now
					items = append(items, resendItem{receiver: peers.agent, connID: peers.agent.connID, seq: seq, msg: qm.msg, attempts: qm.attempts, session: qm.sessionID})
				}
			}
		}
		if peers.viewer != nil {
			if queuedMap, ok := a.pendingByConn[peers.viewer.connID]; ok {
				for seq, qm := range queuedMap {
					if now.Sub(qm.lastSent) < 2*time.Second {
						continue
					}
					if qm.attempts >= 10 {
						toDelete = append(toDelete, struct {
							connID string
							seq    int64
						}{connID: peers.viewer.connID, seq: seq})
						continue
					}
					qm.attempts++
					qm.lastSent = now
					items = append(items, resendItem{receiver: peers.viewer, connID: peers.viewer.connID, seq: seq, msg: qm.msg, attempts: qm.attempts, session: qm.sessionID})
				}
			}
		}
	}
	for _, item := range toDelete {
		if queuedMap, ok := a.pendingByConn[item.connID]; ok {
			delete(queuedMap, item.seq)
		}
	}
	a.mu.Unlock()

	for _, item := range items {
		if err := item.receiver.send(item.msg); err != nil {
			a.logger.Printf("sdp_redelivery_failed seq=%d session=%s err=%v", item.seq, item.session, err)
		}
	}
}

func (a *App) updatePresence(ctx context.Context, deviceID string, online bool) {
	_, err := a.db.ExecContext(
		ctx,
		`INSERT INTO presence (device_id, online, last_seen)
VALUES ($1, $2, now())
ON CONFLICT (device_id)
DO UPDATE SET online = EXCLUDED.online,
              last_seen = now(),
              updated_at = now()`,
		deviceID,
		online,
	)
	if err != nil {
		a.logger.Printf("presence update failed device=%s err=%v", deviceID, err)
	}
}

func (a *App) presenceSweeper(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := a.db.ExecContext(ctx, `UPDATE presence SET online = false, updated_at = now() WHERE online = true AND last_seen < now() - interval '45 seconds'`)
			if err != nil {
				a.logger.Printf("presence sweeper failed: %v", err)
			}
		}
	}
}

func (a *App) insertMessageEvent(ctx context.Context, sessionID, role string, msg WSMessage) error {
	if sessionID == "" {
		return nil
	}

	payload := map[string]interface{}{
		"role": role,
		"type": msg.Type,
	}
	if len(msg.Payload) > 0 {
		var msgPayload interface{}
		if err := json.Unmarshal(msg.Payload, &msgPayload); err == nil {
			payload["message"] = msgPayload
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = a.db.ExecContext(
		ctx,
		`INSERT INTO session_events (session_id, reason, payload)
VALUES ($1, $2, $3::jsonb)`,
		sessionID,
		"signal_message",
		string(payloadJSON),
	)
	return err
}

func insertEventWithTx(ctx context.Context, tx *sql.Tx, sessionID, fromState, toState, reason string, payload interface{}) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO session_events (session_id, from_state, to_state, reason, payload)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5::jsonb)`,
		sessionID,
		fromState,
		toState,
		reason,
		string(payloadJSON),
	)
	return err
}

func (a *App) validateDeviceToken(ctx context.Context, deviceID, deviceToken string) (bool, error) {
	if deviceToken == "" {
		return false, nil
	}
	var expectedHash string
	err := a.db.QueryRowContext(ctx, `SELECT token_hash FROM devices WHERE id = $1`, deviceID).Scan(&expectedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return constantTimeEquals(expectedHash, sha256Hex(deviceToken)), nil
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		events: make(map[string][]time.Time),
	}
}

func (r *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)

	r.mu.Lock()
	defer r.mu.Unlock()

	times := r.events[key]
	filtered := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= limit {
		r.events[key] = filtered
		return false
	}
	filtered = append(filtered, now)
	r.events[key] = filtered

	if now.Sub(r.cleanup) > 5*time.Minute {
		r.cleanup = now
		for k, v := range r.events {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(r.events, k)
			}
		}
	}

	return true
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func respondErr(w http.ResponseWriter, status int, err error) {
	respondJSON(w, status, errorResponse{Error: err.Error()})
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *wsClient) send(msg WSMessage) error {
	if c.closed.Load() {
		return errors.New("websocket is closed")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteJSON(msg); err != nil {
		return err
	}
	return nil
}
