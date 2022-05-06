package authless

import (
	"crypto/sha1"
	"encoding/json"
	"log"
	"mime"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
	"github.com/pkg/errors"
)

type RedirectAuthHandler struct {
	host               string
	successRedirectUrl string
	credChecker        CredCheckerFunc
	jwtService         *token.Service
	storage            storage.Storage
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

	cid, err := randToken()
	if err != nil {
		log.Println("can't make token id")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
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
