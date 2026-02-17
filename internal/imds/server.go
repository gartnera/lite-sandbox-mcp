package imds

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Server implements an IMDSv2-compatible HTTP server that provides AWS credentials
// to sandboxed commands without requiring file access to ~/.aws/credentials.
// Credentials are fetched via AWS STS GetSessionToken and cached until expiry.
type Server struct {
	addr         string
	profile      string
	secretToken  string
	credCache    *credentialCache
	sessionStore *sessionStore
	server       *http.Server
	listener     net.Listener
}

// credentialCache stores temporary AWS credentials and their expiry time.
type credentialCache struct {
	mu          sync.RWMutex
	credentials *sts.GetSessionTokenOutput
	expiresAt   time.Time
}

// sessionStore stores IMDSv2 session tokens and their expiry times.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]time.Time // token -> expiry
}

// NewServer creates a new IMDS server that will listen on the given address
// and use the specified AWS profile for credential lookups.
// The server starts listening immediately but does not serve until Start() is called.
// If addr uses port 0, a random available port is assigned.
func NewServer(addr string, profile string) (*Server, error) {
	// Generate cryptographically secure random token for URL path
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret token: %w", err)
	}
	secretToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Start listening immediately to claim the port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	return &Server{
		addr:        listener.Addr().String(), // Use actual bound address
		profile:     profile,
		secretToken: secretToken,
		credCache:   &credentialCache{},
		sessionStore: &sessionStore{
			sessions: make(map[string]time.Time),
		},
		listener: listener,
	}, nil
}

// Endpoint returns the full IMDS endpoint URL to pass to AWS CLI via
// AWS_EC2_METADATA_SERVICE_ENDPOINT environment variable.
func (s *Server) Endpoint() string {
	return fmt.Sprintf("http://%s/%s", s.addr, s.secretToken)
}

// Start starts the IMDS HTTP server. This blocks until the server is shut down.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// IMDSv2 endpoints with secret token prefix
	prefix := "/" + s.secretToken

	// IMDSv2 token generation endpoint
	mux.HandleFunc("PUT "+prefix+"/latest/api/token", s.handleGetToken)

	// Credential endpoints
	mux.HandleFunc("GET "+prefix+"/latest/meta-data/iam/security-credentials/", s.handleListRoles)
	mux.HandleFunc("GET "+prefix+"/latest/meta-data/iam/security-credentials/{role}", s.handleGetCredentials)

	s.server = &http.Server{
		Handler: mux,
	}

	slog.Info("starting IMDS server", "addr", s.addr, "profile", s.profile)
	return s.server.Serve(s.listener)
}

// Shutdown gracefully shuts down the IMDS server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		err := s.server.Shutdown(ctx)
		// Close listener if server shutdown didn't close it
		if s.listener != nil {
			s.listener.Close()
		}
		return err
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleGetToken implements the IMDSv2 token generation endpoint.
// PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds header.
func (s *Server) handleGetToken(w http.ResponseWriter, r *http.Request) {
	ttlHeader := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
	ttl, err := strconv.Atoi(ttlHeader)
	if err != nil || ttl < 1 || ttl > 21600 {
		ttl = 21600 // Default 6 hours
	}

	// Generate secure session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.Error("failed to generate session token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Store session with expiry
	s.sessionStore.mu.Lock()
	s.sessionStore.sessions[token] = time.Now().Add(time.Duration(ttl) * time.Second)
	s.sessionStore.mu.Unlock()

	slog.Debug("generated IMDSv2 session token", "ttl", ttl)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

// handleListRoles implements the role listing endpoint.
// GET /latest/meta-data/iam/security-credentials/
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if !s.validateSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Return single role name (matches EC2 IMDS behavior)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("sandboxed-role"))
}

// handleGetCredentials implements the credential retrieval endpoint.
// GET /latest/meta-data/iam/security-credentials/{role}
func (s *Server) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.validateSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	role := r.PathValue("role")
	if role != "sandboxed-role" {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Get or refresh credentials
	creds, err := s.getCredentials(r.Context())
	if err != nil {
		slog.Error("failed to get credentials", "error", err)
		http.Error(w, "Failed to get credentials", http.StatusInternalServerError)
		return
	}

	// Format as IMDSv2 JSON response
	response := map[string]interface{}{
		"Code":            "Success",
		"LastUpdated":     time.Now().Format(time.RFC3339),
		"Type":            "AWS-HMAC",
		"AccessKeyId":     *creds.Credentials.AccessKeyId,
		"SecretAccessKey": *creds.Credentials.SecretAccessKey,
		"Token":           *creds.Credentials.SessionToken,
		"Expiration":      creds.Credentials.Expiration.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// validateSession checks if the request has a valid IMDSv2 session token.
func (s *Server) validateSession(r *http.Request) bool {
	token := r.Header.Get("X-aws-ec2-metadata-token")
	if token == "" {
		slog.Warn("request missing IMDSv2 session token")
		return false
	}

	s.sessionStore.mu.RLock()
	expiry, exists := s.sessionStore.sessions[token]
	s.sessionStore.mu.RUnlock()

	if !exists {
		slog.Warn("request with unknown session token")
		return false
	}

	if time.Now().After(expiry) {
		slog.Warn("request with expired session token")
		return false
	}

	return true
}

// getCredentials fetches or returns cached AWS credentials.
// Uses AWS STS GetSessionToken to create temporary credentials from the configured profile.
func (s *Server) getCredentials(ctx context.Context) (*sts.GetSessionTokenOutput, error) {
	s.credCache.mu.Lock()
	defer s.credCache.mu.Unlock()

	// Check if cached credentials are still valid (refresh 5 min before expiry)
	if s.credCache.credentials != nil &&
		time.Now().Before(s.credCache.expiresAt.Add(-5*time.Minute)) {
		slog.Debug("using cached credentials")
		return s.credCache.credentials, nil
	}

	slog.Info("fetching new credentials from AWS STS", "profile", s.profile)

	// Load AWS config with specified profile
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(s.profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Call STS GetSessionToken to get temporary credentials
	stsClient := sts.NewFromConfig(cfg)
	result, err := stsClient.GetSessionToken(ctx, &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(3600), // 1 hour
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get session token: %w", err)
	}

	// Cache credentials
	s.credCache.credentials = result
	s.credCache.expiresAt = *result.Credentials.Expiration

	slog.Info("fetched new credentials",
		"expiration", result.Credentials.Expiration.Format(time.RFC3339))

	return result, nil
}
