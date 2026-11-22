# DevGuard Go Guard (`devguard-go`)

Official Go middleware for **DevGuard** anti-theft protection, domain allowlisting, invoice milestone autolock enforcement, and SEO-safe HTTP 503 lockouts.

Supports standard library **`net/http`**, **Chi**, **Gin**, **Fiber**, **Gorilla Mux**, and any Go HTTP framework.

---

## Features

- **Zero External Dependencies**: Core package uses only the Go standard library (`net/http`, `sync`, `time`, `encoding/json`, `strings`, `fmt`).
- **Fail-Safe Open Policy**: Network timeouts, DNS anomalies, or API downtime will not interrupt client traffic (configurable to `FailSafeClosed`).
- **Domain Authorization**: Enforces authorized hostnames with strict wildcard subdomain matching (`*.example.com`) and port stripping (`host:port`, `[::1]:port`).
- **Milestone Autolock**: Automatically verifies project licensing status with thread-safe `sync.RWMutex` TTL caching.
- **SEO-Safe HTTP 503**: Returns status 503 with `Retry-After: 3600` and `X-Robots-Tag: noindex, nofollow, noarchive` during administrative locks.
- **Bypass Paths**: Bypasses health checks (`/_devguard/health`, `/favicon.ico`, `/robots.txt`) without querying the API.

---

## Installation

```bash
go get github.com/DevGuard-uk/devguard-go
```

---

## Quick Start & Framework Integration

### 1. Standard Library (`net/http`)

```go
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/DevGuard-uk/devguard-go"
)

func main() {
	guard := devguard.New(devguard.Config{
		ProjectID:      "proj_your_project_id",
		// Prefer project SDK key (Portal → Project SDK key). Falls back to APIKey.
		SDKKey:         os.Getenv("DEVGUARD_SDK_KEY"),
		AllowedDomains: []string{"example.com", "*.example.com", "localhost"},
		FailSafe:       devguard.FailSafeOpen,
		Timeout:        2500 * time.Millisecond,
		CacheTTL:       60 * time.Second,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, protected world!")
	})

	// Wrap entire mux with DevGuard middleware
	http.ListenAndServe(":8080", guard.HTTPHandler(mux))
}
```

### 2. Chi Router (`github.com/go-chi/chi/v5`)

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/DevGuard-uk/devguard-go"
)

func main() {
	guard := devguard.New(devguard.Config{
		ProjectID:      "proj_your_project_id",
		AllowedDomains: []string{"example.com", "*.example.com"},
	})

	r := chi.NewRouter()
	r.Use(guard.HTTPHandler)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected with Chi!"))
	})

	http.ListenAndServe(":8080", r)
}
```

### 3. Gin Framework (`github.com/gin-gonic/gin`)

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/DevGuard-uk/devguard-go"
)

func main() {
	guard := devguard.New(devguard.Config{
		ProjectID:      "proj_your_project_id",
		AllowedDomains: []string{"example.com", "*.example.com"},
	})

	r := gin.Default()

	// Adapt net/http middleware using gin.WrapH
	r.Use(gin.WrapH(guard.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))))

	r.GET("/", func(c *gin.Context) {
		c.String(200, "Protected with Gin!")
	})

	r.Run(":8080")
}
```

### 4. Fiber Framework (`github.com/gofiber/fiber/v2`)

```go
package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/DevGuard-uk/devguard-go"
)

func main() {
	guard := devguard.New(devguard.Config{
		ProjectID:      "proj_your_project_id",
		AllowedDomains: []string{"example.com", "*.example.com"},
	})

	app := fiber.New()

	// Adapt net/http middleware for Fiber
	app.Use(adaptor.HTTPMiddleware(guard.HTTPHandler))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Protected with Fiber!")
	})

	app.Listen(":8080")
}
```

---

## Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `ProjectID` | `string` | `""` | DevGuard Project ID. |
| `SDKKey` | `string` | `""` | Preferred project SDK key (`DEVGUARD_SDK_KEY` / Portal → Project SDK key). |
| `APIKey` | `string` | `""` | Legacy API / Master Secret fallback when `SDKKey` is unset. |
| `APIURL` | `string` | `"https://api.devguard.uk"` | Custom DevGuard API endpoint. |
| `FailSafe` | `FailSafeMode` | `FailSafeOpen` | `FailSafeOpen` ("open") or `FailSafeClosed` ("closed"). |
| `Timeout` | `time.Duration` | `2500ms` | Network timeout for API status checks. |
| `CacheTTL` | `time.Duration` | `60s` | Duration project status is cached in-memory. |
| `AllowedDomains` | `[]string` | `nil` (all allowed) | Permitted domains & wildcard subdomains. |
| `BypassPaths` | `[]string` | `["/favicon.ico", "/robots.txt", "/_devguard/health"]` | Paths exempt from checks. |
| `CustomLockHTML` | `string` | `""` | Custom HTML page rendered when locked. |

---

## License

MIT
