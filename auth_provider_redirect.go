package authless

import (
	"crypto/sha1"
	"encoding/json"
	"log"
	"mime"
	"net/http"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type RedirectAuthHandler struct {
	logger.L
	CredChecker        provider.CredChecker
	ProviderName       string
	TokenService       provider.TokenService
	Issuer             string
	AvatarSaver        provider.AvatarSaver
	UserIDFunc         provider.UserIDFunc
	SuccessRedirectUrl string
}

func (m RedirectAuthHandler) Name() string {
	return "r"
}

func (m RedirectAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := m.getCredentials(w, r)
	if err != nil {
		log.Println("failed to parse credentials")
		http.Redirect(w, r, "/login?error=Bad request", http.StatusFound)
		return
	}

	sessOnly := r.URL.Query().Get("sess") == "1"
	if m.CredChecker == nil {
		log.Println("no credential checker")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}

	ok, err := m.CredChecker.Check(creds.Email, creds.Password)
	if err != nil {
		log.Println("failed to check user credentials")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login?error=Incorrect user or password", http.StatusFound)
		return
	}

	userID := m.ProviderName + "_" + token.HashID(sha1.New(), creds.Email)
	if m.UserIDFunc != nil {
		userID = m.ProviderName + "_" + token.HashID(sha1.New(), m.UserIDFunc(creds.Email, r))
	}

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
			Id:       cid,
			Issuer:   m.Issuer,
			Audience: creds.Audience,
		},
		SessionOnly: sessOnly,
	}

	if _, err = m.TokenService.Set(w, claims); err != nil {
		log.Println("failed to set token")
		http.Redirect(w, r, "/login?error=Internal error", http.StatusFound)
		return
	}

	if m.SuccessRedirectUrl == "" {
		m.SuccessRedirectUrl = "/"
	}
	http.Redirect(w, r, m.SuccessRedirectUrl, 301)
}

func (m RedirectAuthHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
}

func (m RedirectAuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	m.TokenService.Reset(w)
	http.Redirect(w, r, "/", 301)
}

// getCredentials extracts user and password from request
func (m RedirectAuthHandler) getCredentials(w http.ResponseWriter, r *http.Request) (credentials, error) {

	// GET /something?user=name&passwd=xyz&aud=bar
	if r.Method == "GET" {
		return credentials{
			Email:    r.URL.Query().Get("email"),
			Password: r.URL.Query().Get("password"),
			Audience: r.URL.Query().Get("aud"),
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
		Audience: r.Form.Get("aud"),
	}, nil
}
