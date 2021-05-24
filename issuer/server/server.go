package server

import (
	"fmt"
	"github.com/go-errors/errors"
	"net/http"
)

type Configuration struct {
	ListenAddress string
	ListenPort    string
}

func Serve(config *Configuration) error {
	addr := fmt.Sprintf("%s:%s", config.ListenAddress, config.ListenPort)
	fmt.Printf("Starting server, listening at %s\n", addr)

	handler := buildHandler()
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		return errors.WrapPrefix(err, "Could not start listening", 0)
	}

	return nil
}

func buildHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/get_ccm", getCreateCredentialMessage)

	return handler
}

func getCreateCredentialMessage(w http.ResponseWriter, r *http.Request) {
	writeError(w, errors.Errorf("Not yet implemented"))
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
