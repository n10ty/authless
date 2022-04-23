package authless

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

const (
	// MaxHTTPBodySize defines max http body size
	MaxHTTPBodySize = 1024 * 1024
)

// ApiAuthHandler aims to handle unauthorized requests and errors as json
type ApiAuthHandler struct {
	logger.L
	CredChecker        provider.CredChecker
	ProviderName       string
	TokenService       provider.TokenService
	Issuer             string
	AvatarSaver        provider.AvatarSaver
	UserIDFunc         provider.UserIDFunc
	SuccessRedirectUrl string
}

func (m ApiAuthHandler) Name() string {
	return "r"
}

func (m ApiAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := m.getCredentials(w, r)
	if err != nil {
		rest.SendErrorJSON(w, r, m.L, http.StatusBadRequest, err, "failed to parse credentials")
		return
	}
	sessOnly := r.URL.Query().Get("sess") == "1"
	if m.CredChecker == nil {
		rest.SendErrorJSON(w, r, m.L, http.StatusInternalServerError,
			errors.New("no credential checker"), "no credential checker")
		return
	}
	ok, err := m.CredChecker.Check(creds.Email, creds.Password)
	if err != nil {
		rest.SendErrorJSON(w, r, m.L, http.StatusInternalServerError, err, "failed to check user credentials")
		return
	}
	if !ok {
		rest.SendErrorJSON(w, r, m.L, http.StatusForbidden, nil, "incorrect email or password")
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
		rest.SendErrorJSON(w, r, m.L, http.StatusInternalServerError, err, "can't make token id")
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
		rest.SendErrorJSON(w, r, m.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	if m.SuccessRedirectUrl == "" {
		m.SuccessRedirectUrl = "/"
	}
	rest.RenderJSON(w, claims.User)
}

func (m ApiAuthHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
}

func (m ApiAuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	m.TokenService.Reset(w)
	http.Redirect(w, r, "/", 301)
}

// credentials holds user credentials
type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Audience string `json:"aud"`
}

// getCredentials extracts user and password from request
func (m ApiAuthHandler) getCredentials(w http.ResponseWriter, r *http.Request) (credentials, error) {

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

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "can't get random")
	}
	s := sha1.New()
	if _, err := s.Write(b); err != nil {
		return "", errors.Wrap(err, "can't write randoms to sha1")
	}
	return fmt.Sprintf("%x", s.Sum(nil)), nil
}
