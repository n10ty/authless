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

type RedirectAuthHandler struct {
	host               string
	successRedirectUrl string
	credChecker        CredCheckerFunc
	jwtService         *token.Service
	storage            storage.Storage
	tokenSenderFunc    TokenSenderFunc
	remindPasswordFunc RemindPasswordFunc
}

func NewRedirectAuthHandler(host string, successRedirectUrl string, credChecker CredCheckerFunc, jwtService *token.Service, storage storage.Storage) *RedirectAuthHandler {
	return &RedirectAuthHandler{host: host, successRedirectUrl: successRedirectUrl, credChecker: credChecker, jwtService: jwtService, storage: storage}
}

func (a *RedirectAuthHandler) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/register?error=Bad request", http.StatusMovedPermanently)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		http.Redirect(w, r, "/register?error=Bad request", http.StatusMovedPermanently)
		return
	}

	if !passwordValid(password) {
		http.Redirect(w, r, "/register?error=Password must be contains at least 6 symbols", http.StatusMovedPermanently)
		return
	}

	if !emailValid(email) {
		http.Redirect(w, r, "/register?error=Invalid email", http.StatusMovedPermanently)
		return
	}

	_, err := a.storage.GetUser(email)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/register?error=Email already exists", http.StatusMovedPermanently)
		return
	}

	user, err := storage.NewUser(email, password)
	if err != nil {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/register?error=Internal error", http.StatusMovedPermanently)
		return
	}

	err = a.storage.CreateUser(user)
	if err != nil {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/register?error=Internal error", http.StatusMovedPermanently)
		return
	}

	if a.tokenSenderFunc != nil {
		if err := a.tokenSenderFunc(email, user.ConfirmationToken); err != nil {
			log.Errorf("error during send activation token: %s", err)
		}
	}

	http.Redirect(w, r, "/success", http.StatusFound)
}

func (a *RedirectAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := a.getCredentials(w, r)
	if err != nil {
		log.Println("failed to parse credentials")
		http.Redirect(w, r, "/login?error=Bad request", http.StatusFound)
		return
	}

	sessOnly := r.URL.Query().Get("sess") == "1"
	if a.credChecker == nil {
		log.Println("no credential checker")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}

	ok, err := a.credChecker.Check(creds.Email, creds.Password)
	if err != nil {
		log.Println("failed to check user credentials")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login?error=Incorrect email or password", http.StatusFound)
		return
	}

	userID := token.HashID(sha1.New(), creds.Email)

	u := token.User{
		Name: creds.Email,
		ID:   userID,
	}

	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:     RandToken(TokenLength),
			Issuer: a.host,
		},
		SessionOnly: sessOnly,
	}

	if _, err = a.jwtService.Set(w, claims); err != nil {
		log.Println("failed to set token")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}

	if a.successRedirectUrl == "" {
		a.successRedirectUrl = "/"
	}
	http.Redirect(w, r, a.successRedirectUrl, 301)
}

func (a *RedirectAuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	a.jwtService.Reset(w)
	http.Redirect(w, r, "/", 301)
}

func (a *RedirectAuthHandler) ActivationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/activate-result?error=Bad request", http.StatusFound)
		return
	}

	user, err := a.storage.GetUserByConfirmationToken(token)
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

// getCredentials extracts user and password from request
func (a *RedirectAuthHandler) getCredentials(w http.ResponseWriter, r *http.Request) (credentials, error) {

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

func (a *RedirectAuthHandler) RemindPasswordHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		log.Info("remind password: empty email")
		renderJSONWithStatus(w, JSON{"error": "bad request"}, http.StatusBadRequest)
		return
	}

	user, err := a.storage.GetUser(email)
	if err != nil {
		log.Printf("remind password: %s", err)
		renderJSONWithStatus(w, nil, http.StatusOK)
		return
	}
	if !user.Enabled {
		renderJSONWithStatus(w, nil, http.StatusOK)
		return
	}

	user.RegenerateChangePasswordToken()
	if err := a.storage.UpdateUser(user); err != nil {
		log.Printf("update user error: %s", err)
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}
	if err := a.remindPasswordFunc(email, user.ChangePasswordToken); err != nil {
		log.Printf("remind password execution error: %s", err)
		renderJSONWithStatus(w, JSON{"error": "internal error"}, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *RedirectAuthHandler) SetActivationTokenSenderFunc(senderFunc TokenSenderFunc) {
	a.tokenSenderFunc = senderFunc
}

func (a *RedirectAuthHandler) SetRemindPasswordFunc(remindPasswordFunc RemindPasswordFunc) {
	a.remindPasswordFunc = remindPasswordFunc
}
