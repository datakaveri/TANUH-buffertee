package server

import (
	"io"
	"log"
	"net/http"

	"github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
)

const bufferManagerURL = "http://127.0.0.1:4100"

// Server wires HTTP handlers to a ServeMux.
type Server struct {
	builder *bundle.Builder
	mux     *http.ServeMux
}

// New creates a Server and registers all routes.
func New(b *bundle.Builder) *Server {
	s := &Server{builder: b, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /v1/attest",                    s.HandleAttest)
	s.mux.HandleFunc("POST /v1/submit",                   s.HandleSubmit)
	// Binary file upload — large files sent over TLS, hashes committed via HPKE
	s.mux.HandleFunc("PUT /v1/upload/{job_id}/model",     s.HandleUploadModel)
	s.mux.HandleFunc("PUT /v1/upload/{job_id}/weights",   s.HandleUploadWeights)
	s.mux.HandleFunc("GET /v1/status/{job_id}",           s.HandleStatus)
	s.mux.HandleFunc("GET /v1/queue",                     s.HandleQueue)
	s.mux.HandleFunc("GET /v1/results/{job_id}",          s.HandleResults)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return s
}

// Handler returns the HTTP handler with CORS middleware.
func (s *Server) Handler() http.Handler {
	return corsMiddleware(s.mux)
}

// corsMiddleware adds CORS headers and handles OPTIONS preflights.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-RATLS-Nonce, X-RATLS-Browser-HPKE, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HandleStatus proxies GET /v1/status/{job_id} → Flask /buffer/jobs/:id
func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	proxyGet(w, bufferManagerURL+"/buffer/jobs/"+jobID)
}

// HandleQueue proxies GET /v1/queue → Flask /buffer/jobs
func (s *Server) HandleQueue(w http.ResponseWriter, r *http.Request) {
	proxyGet(w, bufferManagerURL+"/buffer/jobs")
}

// HandleResults proxies GET /v1/results/{job_id} → Flask results endpoint
func (s *Server) HandleResults(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	proxyGet(w, bufferManagerURL+"/buffer/jobs/"+jobID+"/results")
}

func proxyGet(w http.ResponseWriter, url string) {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		log.Printf("proxy GET %s: %v", url, err)
		http.Error(w, "buffer manager unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}
