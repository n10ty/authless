package authless

import (
	"crypto/sha1"
	"encoding/json"
	"mime"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MaxHTTPBodySize defines max http body size
const MaxHTTPBodySize = 1024 * 1024

// credentials holds user credentials
type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ApiAuthHandler aims to handle unauthorized requests and errors as json
type ApiAuthHandler struct {
	host               string
	successRedirectUrl string
	credChecker        CredCheckerFunc
	jwtService         *token.Service
	storage            storage.Storage
	tokenSenderFunc    TokenSenderFunc
	remindPasswordFunc RemindPasswordFunc
}

func NewApiAuthHandler(host string, successRedirectUrl string, credChecker CredCheckerFunc, jwtService *token.Service, storage storage.Storage) *ApiAuthHandler {
	return &ApiAuthHandler{host: host, successRedirectUrl: successRedirectUrl, credChecker: credChecker, jwtService: jwtService, storage: storage}
}

func (a *ApiAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := a.getCredentials(w, r)

	if err != nil {
		renderJSONWithStatus(w, JSON{"error": "failed to parse credentials"}, http.StatusBadRequest)
		return
	}
	sessOnly := r.URL.Query().Get("sess") == "1"
	if a.credChecker == nil {
		renderJSONWithStatus(w, JSON{"error": "no credential checker"}, http.StatusInternalServerError)
		return
	}
	ok, err := a.credChecker.Check(creds.Email, creds.Password)
	log.Debugf("LOGIN check: %v", ok)
	if err != nil {
		renderJSONWithStatus(w, JSON{"error": "failed to check user credentials"}, http.StatusInternalServerError)
		return
	}
	if !ok {
		renderJSONWithStatus(w, JSON{"error": "incorrect email or password"}, http.StatusForbidden)
		return
	}

	userID := token.HashID(sha1.New(), creds.Email)

	u := token.User{
		Name: creds.Email,
		ID:   userID,
	}

	cid, err := randToken()
	if err != nil {
		renderJSONWithStatus(w, JSON{"error": "can't make token id"}, http.StatusInternalServerError)
		return
	}

	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:     cid,
			Issuer: a.host,
		},
		SessionOnly: sessOnly,
	}

	if _, err = a.jwtService.Set(w, claims); err != nil {
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}

	if a.successRedirectUrl == "" {
		a.successRedirectUrl = "/"
	}

	tkn, err := a.jwtService.Token(claims)
	if err != nil {
		log.Printf("internal error: %s\n", err)
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}

	renderJSONWithStatus(w, JSON{"user": claims.User, "jwt": tkn}, http.StatusOK)
}

func (a *ApiAuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	a.jwtService.Reset(w)
	http.Redirect(w, r, "/", 301)
}

func (a *ApiAuthHandler) ActivationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/activate-result?error=Bad request", http.StatusFound)
		return
	}

	user, err := a.storage.GetUserByToken(token)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/activate-result?error=Internal error", http.StatusFound)
		return
	} else if errors.Is(err, storage.ErrUserNotFound) {
		http.Redirect(w, r, "/activate-result?error=Bad token", http.StatusFound)
		return
	}

	if user.ConfirmationToken != token {
		http.Redirect(w, r, "/activate-result?error=Bad token", http.StatusFound)
		return
	}

	user.Enabled = true
	if err := a.storage.UpdateUser(user); err != nil {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/activate-result?error=Internal error", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/activate-result", http.StatusFound)
}

func (a *ApiAuthHandler) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		renderJSONWithStatus(w, JSON{"error": "bad request"}, http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		renderJSONWithStatus(w, JSON{"error": "bad request"}, http.StatusBadRequest)
		return
	}

	if !passwordValid(password) {
		renderJSONWithStatus(w, JSON{"error": "password must be contains at least 6 symbols"}, http.StatusBadRequest)
		return
	}

	if !emailValid(email) {
		renderJSONWithStatus(w, JSON{"error": "invalid email"}, http.StatusBadRequest)
		return
	}

	_, err := a.storage.GetUser(email)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Printf("internal error: %s", err)
		renderJSONWithStatus(w, JSON{"error": "email already exists"}, http.StatusBadRequest)
		return
	}

	user, err := storage.NewUser(email, password)
	if err != nil {
		log.Printf("internal error: %s", err)
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}

	err = a.storage.CreateUser(user)
	if err != nil {
		log.Printf("internal error: %s", err)
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}

	if a.tokenSenderFunc != nil {
		if err := a.tokenSenderFunc(email, user.ConfirmationToken); err != nil {
			log.Errorf("error during send activation token: %s", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// getCredentials extracts user and password from request
func (a *ApiAuthHandler) getCredentials(w http.ResponseWriter, r *http.Request) (credentials, error) {

	// GET /something?user=name&passwd=xyz&aud=bar
	if r.Method == "GET" {
		return credentials{
			Email:    r.URL.Query().Get("email"),
			Password: r.URL.Query().Get("password"),
		}, nil
	}

	if r.Method != "POST" {
		return credentials{}, errors.Errorf("method %s not supported", r.Method)
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, MaxHTTPBodySize)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			return credentials{}, err
		}
		contentType = mt
	}

	// POST with json body
	if contentType == "application/json" {
		var creds credentials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			return credentials{}, errors.Wrap(err, "failed to parse request body")
		}
		return creds, nil
	}

	// POST with form
	if err := r.ParseForm(); err != nil {
		return credentials{}, errors.Wrap(err, "failed to parse request")
	}

	return credentials{
		Email:    r.Form.Get("email"),
		Password: r.Form.Get("password"),
	}, nil
}

func (a *ApiAuthHandler) RemindPasswordHandler(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (a *ApiAuthHandler) SetActivationTokenSenderFunc(senderFunc TokenSenderFunc) {
	a.tokenSenderFunc = senderFunc
}

func (a *ApiAuthHandler) SetRemindPasswordFunc(remindPasswordFunc RemindPasswordFunc) {
	a.remindPasswordFunc = remindPasswordFunc
}
