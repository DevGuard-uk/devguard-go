// Package devguard provides HTTP middleware for DevGuard web application protection.
// It enforces domain allowlists, bypass paths, and project locking based on status from the DevGuard API.
package devguard

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FailSafeMode determines behavior when API calls fail or time out.
type FailSafeMode string

const (
	// FailSafeOpen allows requests through if DevGuard API is unreachable.
	FailSafeOpen FailSafeMode = "open"
	// FailSafeClosed blocks requests (503) if DevGuard API is unreachable.
	FailSafeClosed FailSafeMode = "closed"
)

// Config configures the DevGuard middleware.
type Config struct {
	ProjectID      string
	SDKKey         string        // Preferred project SDK key (dg_sdk_*); wins over APIKey
	APIKey         string        // Legacy API / Master Secret fallback
	APIURL         string        // Default: "https://api.devguard.uk"
	FailSafe       FailSafeMode  // Default: FailSafeOpen ("open")
	Timeout        time.Duration // Default: 2500 * time.Millisecond
	CacheTTL       time.Duration // Default: 60 * time.Second
	AllowedDomains []string
	BypassPaths    []string // Default: []string{"/favicon.ico", "/robots.txt", "/_devguard/health"}
	CustomLockHTML string
}

type cacheEntry struct {
	status    string
	expiresAt time.Time
}

// Guard is the central DevGuard protection engine.
type Guard struct {
	config Config
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]cacheEntry
}

// New creates a new Guard instance with normalized defaults.
func New(cfg Config) *Guard {
	if strings.TrimSpace(cfg.SDKKey) != "" {
		cfg.APIKey = strings.TrimSpace(cfg.SDKKey)
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.devguard.uk"
	}
	if cfg.FailSafe == "" {
		cfg.FailSafe = FailSafeOpen
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2500 * time.Millisecond
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 60 * time.Second
	}
	if len(cfg.BypassPaths) == 0 {
		cfg.BypassPaths = []string{"/favicon.ico", "/robots.txt", "/_devguard/health"}
	}

	return &Guard{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		cache:  make(map[string]cacheEntry),
	}
}

// SetHTTPClient configures a custom HTTP client for the guard.
func (g *Guard) SetHTTPClient(client *http.Client) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.client = client
}

// ClearCache invalidates any cached project statuses.
func (g *Guard) ClearCache() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cache = make(map[string]cacheEntry)
}

func normalizeHost(rawHost string) string {
	host := strings.TrimSpace(strings.ToLower(rawHost))
	if host == "" {
		return ""
	}

	// Reject invalid / header injection characters (CRLF, null, whitespace, slashes, ?, #, @)
	if strings.ContainsAny(host, "\r\n\x00/ \t\v\f\\?#@") {
		return ""
	}

	// Try splitting host and port via net.SplitHostPort (e.g. host:port, [::1]:port)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") {
		endIdx := strings.Index(host, "]")
		if endIdx != -1 {
			host = host[1:endIdx]
		}
	} else if strings.Count(host, ":") == 1 {
		// Single colon hostname:port fallback
		host = strings.Split(host, ":")[0]
	}

	// Strip trailing dot
	host = strings.TrimSuffix(host, ".")
	return host
}

// CheckDomain verifies whether the provided host satisfies the configured AllowedDomains.
// If AllowedDomains is empty, all hosts are permitted.
func (g *Guard) CheckDomain(host string) bool {
	if len(g.config.AllowedDomains) == 0 {
		return true
	}

	target := normalizeHost(host)
	if target == "" {
		return false
	}

	for _, rawPat := range g.config.AllowedDomains {
		pat := strings.TrimSpace(strings.ToLower(rawPat))
		if pat == "" {
			continue
		}

		if pat == "*" {
			return true
		}

		if strings.HasPrefix(pat, "*.") {
			base := normalizeHost(pat[2:])
			if base == "" {
				continue
			}

			if target == base || strings.HasSuffix(target, "."+base) {
				return true
			}
			continue
		}

		normPat := normalizeHost(pat)
		if normPat != "" && target == normPat {
			return true
		}
	}

	return false
}

func (g *Guard) isBypassed(path string) bool {
	for _, bp := range g.config.BypassPaths {
		trimmedBP := strings.TrimSpace(bp)
		if trimmedBP == "" {
			continue
		}

		// Exact match
		if path == trimmedBP {
			return true
		}

		// Directory or prefix match
		if strings.HasSuffix(trimmedBP, "/") {
			if strings.HasPrefix(path, trimmedBP) {
				return true
			}
		} else {
			if strings.HasPrefix(path, trimmedBP+"/") {
				return true
			}
		}
	}
	return false
}

type statusResponse struct {
	Status string `json:"status"`
}

// FetchStatus queries the DevGuard API for the current project status.
func (g *Guard) FetchStatus(projectID string) (string, error) {
	if projectID == "" {
		return "active", nil
	}

	baseURL := strings.TrimRight(g.config.APIURL, "/")
	reqURL := fmt.Sprintf("%s/api/v1/projects/%s/status", baseURL, projectID)

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "DevGuard-Go/1.0.0")
	req.Header.Set("Accept", "application/json")
	if g.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.config.APIKey)
	}

	g.mu.RLock()
	client := g.client
	g.mu.RUnlock()

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("DevGuard API returned HTTP %d", resp.StatusCode)
	}

	var res statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("failed to decode DevGuard API response: %w", err)
	}

	status := strings.ToLower(strings.TrimSpace(res.Status))
	if status == "" {
		status = "active"
	}

	return status, nil
}

func (g *Guard) getStatus(projectID string) (string, error) {
	g.mu.RLock()
	entry, found := g.cache[projectID]
	if found && time.Now().Before(entry.expiresAt) {
		g.mu.RUnlock()
		return entry.status, nil
	}
	g.mu.RUnlock()

	status, err := g.FetchStatus(projectID)
	if err != nil {
		return "", err
	}

	g.mu.Lock()
	g.cache[projectID] = cacheEntry{
		status:    status,
		expiresAt: time.Now().Add(g.config.CacheTTL),
	}
	g.mu.Unlock()

	return status, nil
}

const defaultLockTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow, noarchive" />
  <title>Service Unavailable - DevGuard</title>
  <style>
    body {
      background-color: #0b0f19;
      color: #f3f4f6;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 1.5rem;
      box-sizing: border-box;
    }
    .container {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      max-width: 520px;
      padding: 2.5rem;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; color: #f87171; }
    p { color: #9ca3af; line-height: 1.6; margin-bottom: 1.5rem; }
    .meta { font-size: 0.85rem; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 1rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Service Temporarily Unavailable</h1>
    <p>This application is temporarily suspended pending administrative milestone verification.</p>
    <div class="meta">DevGuard Protection Active &bull; Project: %s</div>
  </div>
</body>
</html>`

func (g *Guard) serveLock(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "3600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("X-DevGuard-Status", "locked")
	w.WriteHeader(http.StatusServiceUnavailable)

	if g.config.CustomLockHTML != "" {
		w.Write([]byte(g.config.CustomLockHTML))
		return
	}

	pid := g.config.ProjectID
	if pid == "" {
		pid = "Protected"
	}
	w.Write([]byte(fmt.Sprintf(defaultLockTemplate, pid)))
}

// HTTPHandler is standard net/http middleware compatible with Chi, gorilla/mux, and stdlib.
func (g *Guard) HTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Bypass paths check
		if g.isBypassed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Domain verification
		if !g.CheckDomain(r.Host) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-DevGuard-Status", "domain_unauthorized")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Domain unauthorized by DevGuard")
			return
		}

		// If no project ID is configured, allow through
		if g.config.ProjectID == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Status check against DevGuard API (cached)
		status, err := g.getStatus(g.config.ProjectID)
		if err != nil {
			if g.config.FailSafe == FailSafeClosed {
				g.serveLock(w)
				return
			}
			// FailSafeOpen: log warning and delegate
			log.Printf("[DevGuard] Status check failed: %v. Fail-safe open: passing through.", err)
			next.ServeHTTP(w, r)
			return
		}

		// 4. Status evaluation
		switch status {
		case "locked", "autolocked", "payment_past_due":
			g.serveLock(w)
			return
		default: // "active", "warning", etc.
			next.ServeHTTP(w, r)
			return
		}
	})
}

// Middleware adapts standard http.HandlerFunc to standard middleware chains.
func (g *Guard) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.HTTPHandler(next).ServeHTTP(w, r)
	}
}
