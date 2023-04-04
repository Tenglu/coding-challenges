package api

import (
	"encoding/json"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"net/http"
)

// Response is the generic API response container.
type Response struct {
	Data interface{} `json:"data"`
}

// ErrorResponse is the generic error API response container.
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// Server manages HTTP requests and dispatches them to the appropriate services.
type Server struct {
	listenAddress string
	repository    persistence.InMemoryDeviceRepository
}

// NewServer is a factory to instantiate a new Server.
func NewServer(listenAddress string, repository *persistence.InMemoryDeviceRepository) *Server {
	return &Server{
		listenAddress: listenAddress,
		repository:    *repository,
	}
}

// Run registers all HandlerFuncs for the existing HTTP routes and starts the Server.
func (s *Server) Run() error {
	mux := http.NewServeMux()

	mux.Handle("/api/v0/health", http.HandlerFunc(s.Health))
	mux.HandleFunc("/api/v0/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.ListDevices(w)
			return
		}
		if r.Method == http.MethodPost {
			s.CreateSignatureDevice(w, r)
			return
		}
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	})
	mux.Handle("/api/v0/signature", http.HandlerFunc(s.SignTransaction))

	return http.ListenAndServe(s.listenAddress, mux)
}

// WriteInternalError writes a default internal error message as an HTTP response.
func WriteInternalError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

// WriteErrorResponse takes an HTTP status code and a slice of errors
// and writes those as an HTTP error response in a structured format.
func WriteErrorResponse(w http.ResponseWriter, code int, errors []string) {
	w.WriteHeader(code)

	errorResponse := ErrorResponse{
		Errors: errors,
	}

	bytes, err := json.Marshal(errorResponse)
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}

// WriteAPIResponse takes an HTTP status code and a generic data struct
// and writes those as an HTTP response in a structured format.
func WriteAPIResponse(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)

	response := Response{
		Data: data,
	}

	bytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}
