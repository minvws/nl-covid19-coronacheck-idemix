package server

import (
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
	"net/http"
)

type Configuration struct {
	ListenAddress string
	ListenPort    string

	PublicKeyId    string
	PublicKeyPath  string
	PrivateKeyPath string
}

type server struct {
	config *Configuration
	issuer *issuer.Issuer
}

// TODO: Move this into the call to prepareIssue
var magicAmountOfCredentials = 28

func Run(config *Configuration) error {
	// Create local signer and issuer
	var err error
	localSigner, err := localsigner.New(config.PublicKeyId, config.PublicKeyPath, config.PrivateKeyPath)
	if err != nil {
		return errors.WrapPrefix(err, "Could not create local signer", 0)
	}

	iss := issuer.New(localSigner)

	// Serve
	s := &server{
		config: config,
		issuer: iss,
	}

	err = s.Serve()
	if err != nil {
		return errors.WrapPrefix(err, "Could not start server", 0)
	}

	return nil
}

func (s *server) Serve() error {
	addr := fmt.Sprintf("%s:%s", s.config.ListenAddress, s.config.ListenPort)
	fmt.Printf("Starting server, listening at %s\n", addr)

	handler := s.buildHandler()
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		return errors.WrapPrefix(err, "Could not start listening", 0)
	}

	return nil
}

func (s *server) buildHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/prepare_issue", s.handlePrepareIssue)
	handler.HandleFunc("/issue", s.handleIssue)

	return handler
}

func (s *server) handlePrepareIssue(w http.ResponseWriter, r *http.Request) {
	pim, err := s.issuer.PrepareIssue(magicAmountOfCredentials)
	if err != nil {
		writeError(w, err)
		return
	}

	responseJson, err := json.Marshal(pim)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON marshal prepareIssueMessage", 0))
		return
	}

	w.WriteHeader(200)
	_, _ = w.Write(responseJson)
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	issueMessage := &issuer.IssueMessage{}
	err := json.NewDecoder(r.Body).Decode(issueMessage)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON unmarshal issueMessage", 0))
		return
	}

	// TODO: Better handle this with a separate unmarshaler
	if issueMessage.CredentialsAttributes == nil || issueMessage.IssueCommitmentMessage == nil || issueMessage.PrepareIssueMessage == nil {
		writeError(w, errors.Errorf("A required field of issueMessage is missing"))
		return
	}

	createCredentialMessages, err := s.issuer.Issue(issueMessage)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not issue credentials", 0))
		return
	}

	responseJson, err := json.Marshal(createCredentialMessages)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON marshal createCredentialMessages", 0))
		return
	}

	w.WriteHeader(200)
	_, _ = w.Write(responseJson)
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
