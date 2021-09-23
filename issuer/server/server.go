package server

import (
	"encoding/json"
	"fmt"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common/pool"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
	gabipool "github.com/privacybydesign/gabi/pool"
)

type Configuration struct {
	ListenAddress string
	ListenPort    string

	PublicKeyId    string
	PublicKeyPath  string
	PrivateKeyPath string

	StaticPublicKeyId    string
	StaticPublicKeyPath  string
	StaticPrivateKeyPath string

	PrimePoolSize        uint64 // Size of the pool (in number of big ints)
	PrimePoolLwm         uint64 // Low water mark for depletion detection
	PrimePoolHwm         uint64 // high water mark for depletion detection
	PrimePoolPrimeStart  uint   // Prime number generator bit start
	PrimePoolPrimeLength uint   // prime number generator bit length
	PrimePoolMaxCores    int    // Number of cores to use for prime generation
}

type server struct {
	config        *Configuration
	dynamicIssuer *issuer.Issuer
	staticIssuer  *issuer.Issuer
}

type PrepareIssueRequest struct {
	CredentialAmount int
}

type IssueStaticResponse struct {
	QR string `json:"qr"`
}

func Run(config *Configuration) error {
	staticPrimePool := gabipool.NewRandomPool()
	dynamicPrimePool := gabipool.NewRandomPool()

	// Initialize dynamic in-memory prime pool when its configured size > 0
	if config.PrimePoolSize > 0 {
		dynamicPrimePool = pool.NewMemoryPool(
			config.PrimePoolSize,
			config.PrimePoolLwm,
			config.PrimePoolHwm,
			config.PrimePoolPrimeStart,
			config.PrimePoolPrimeLength,
			config.PrimePoolMaxCores,
		)
	}

	var err error
	dynamicSigner, err := localsigner.New(config.PublicKeyId, config.PublicKeyPath, config.PrivateKeyPath, dynamicPrimePool)
	if err != nil {
		return errors.WrapPrefix(err, "Could not create local signer", 0)
	}

	staticSigner, err := localsigner.New(config.StaticPublicKeyId, config.StaticPublicKeyPath, config.StaticPrivateKeyPath, staticPrimePool)
	if err != nil {
		return errors.WrapPrefix(err, "Could not create local signer", 0)
	}

	// Serve
	s := &server{
		config:        config,
		dynamicIssuer: issuer.New(dynamicSigner),
		staticIssuer:  issuer.New(staticSigner),
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
	handler.Handle("/prepare_issue", jsonPostHandler(http.HandlerFunc(s.handlePrepareIssue)))

	handler.Handle("/stats", http.HandlerFunc(s.handleStats))

	handler.Handle("/issue", jsonPostHandler(http.HandlerFunc(s.handleIssue)))
	handler.Handle("/issue_static", jsonPostHandler(http.HandlerFunc(s.handleIssueStatic)))

	return handler
}

func jsonPostHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeError(w, http.StatusMethodNotAllowed, errors.Errorf("Expected POST method"))
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			writeError(w, http.StatusBadRequest, errors.Errorf("Expect application/json Content-Type"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	responseJson, err := s.dynamicIssuer.Signer.GetPrimePool().StatsJSON()
	if err != nil {
		msg := "Could not JSON marshal statistics"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(responseJson)
}

func (s *server) handlePrepareIssue(w http.ResponseWriter, r *http.Request) {
	pir := &PrepareIssueRequest{}
	err := json.NewDecoder(r.Body).Decode(pir)
	if err != nil {
		msg := "Could not JSON unmarshal prepare issue request"
		writeError(w, http.StatusBadRequest, errors.WrapPrefix(err, msg, 0))
		return
	}

	pim, err := s.dynamicIssuer.PrepareIssue(pir.CredentialAmount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	responseJson, err := json.Marshal(pim)
	if err != nil {
		msg := "Could not JSON marshal prepareIssueMessage"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(responseJson)
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	issueMessage := &issuer.IssueMessage{}
	err := json.NewDecoder(r.Body).Decode(issueMessage)
	if err != nil {
		msg := "Could not JSON unmarshal issue message"
		writeError(w, http.StatusBadRequest, errors.WrapPrefix(err, msg, 0))
		return
	}

	// TODO: Better handle this with a separate unmarshaler
	if issueMessage.CredentialsAttributes == nil || issueMessage.IssueCommitmentMessage == nil || issueMessage.PrepareIssueMessage == nil {
		msg := "A required field of issue message is missing"
		writeError(w, http.StatusBadRequest, errors.Errorf(msg))
		return
	}

	createCredentialMessages, err := s.dynamicIssuer.Issue(issueMessage)
	if err != nil {
		msg := "Could not issue credentials"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	responseJson, err := json.Marshal(createCredentialMessages)
	if err != nil {
		msg := "Could not JSON marshal create credential message"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	_, _ = w.Write(responseJson)
}

func (s *server) handleIssueStatic(w http.ResponseWriter, r *http.Request) {
	sim := &issuer.StaticIssueMessage{}
	err := json.NewDecoder(r.Body).Decode(sim)
	if err != nil {
		msg := "Could not JSON unmarshal static issue message"
		writeError(w, http.StatusBadRequest, errors.WrapPrefix(err, msg, 0))
		return
	}

	proofPrefixed, err := s.staticIssuer.IssueStatic(sim)
	if err != nil {
		msg := "Could not issue static proof"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	responseJson, err := json.Marshal(&IssueStaticResponse{QR: string(proofPrefixed)})
	if err != nil {
		msg := "Could not JSON marshal static proof"
		writeError(w, http.StatusInternalServerError, errors.WrapPrefix(err, msg, 0))
		return
	}

	_, _ = w.Write(responseJson)
}

func writeError(w http.ResponseWriter, statusCode int, err error) {
	fmt.Println(err.Error())
	http.Error(w, err.Error(), statusCode)
}
