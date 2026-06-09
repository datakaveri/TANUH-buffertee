package server

import (
    "net/http"

    "github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
)

// Server wires HTTP handlers to a ServeMux.
type Server struct {
    builder *bundle.Builder
    mux     *http.ServeMux
}

// New creates a Server and registers all routes.
func New(b *bundle.Builder) *Server {
    s := &Server{builder: b, mux: http.NewServeMux()}

    // RA-TLS attestation flow
    s.mux.HandleFunc("GET /v1/attest", s.HandleAttest)

    // Old HPKE submit — kept for backward compatibility
    s.mux.HandleFunc("POST /v1/submit", s.HandleSubmit)

    // New symmetric key flow — browser encrypts model with KMS symmetric key
    s.mux.HandleFunc("POST /v1/submit/model", s.HandleSubmitModel)

    // Job management — Processing TEE polls this to get queued jobs
    s.mux.HandleFunc("GET /v1/jobs", s.HandleListJobs)

    // Health check
    s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusOK)
    })

    return s
}

// Handler returns the HTTP handler with CORS middleware applied.
func (s *Server) Handler() http.Handler {
    return corsMiddleware(s.mux)
}

// corsMiddleware adds CORS headers and handles OPTIONS preflights.
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "X-RATLS-Nonce, X-RATLS-Browser-HPKE, Content-Type")
        w.Header().Set("Access-Control-Max-Age", "86400")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next.ServeHTTP(w, r)
    })
}
