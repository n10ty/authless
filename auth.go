package authless

import (
	_ "embed"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

var a *Auth

const AuthTypeRedirect = "redirect"
const AuthTypeAPI = "api"

type Auth struct {
	storage         storage.Storage
	config          *Config
	tokenSenderFunc TokenSenderFunc
	authHandler     AuthHandler
	jwtService      *token.Service
}

func initAuth(config *Config) error {
	loglevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		log.Warnf("Unknown log level: %s. Set to INFO", loglevel)
		loglevel = log.InfoLevel
	}
	log.SetLevel(loglevel)
	log.Infof("Log level: %s", loglevel)

	storage, err := storage.NewStorage(config.Storage)
	if err != nil {
		return err
	}

	a = newAuth(config, storage)

	return nil
}

func newAuth(config *Config, storage storage.Storage) *Auth {
	opts := config.toLibCfg()

	credChecker := CredCheckerFunc(func(user, password string) (ok bool, err error) {
		return storage.AuthenticateUser(user, password)
	})

	jwtService := token.NewService(token.Opts{
		SecretReader:    opts.SecretReader,
		ClaimsUpd:       opts.ClaimsUpd,
		SecureCookies:   opts.SecureCookies,
		TokenDuration:   opts.TokenDuration,
		CookieDuration:  opts.CookieDuration,
		DisableXSRF:     opts.DisableXSRF,
		DisableIAT:      opts.DisableIAT,
		JWTCookieName:   opts.JWTCookieName,
		JWTCookieDomain: opts.JWTCookieDomain,
		JWTHeaderKey:    opts.JWTHeaderKey,
		XSRFCookieName:  opts.XSRFCookieName,
		XSRFHeaderKey:   opts.XSRFHeaderKey,
		SendJWTHeader:   opts.SendJWTHeader,
		JWTQuery:        opts.JWTQuery,
		Issuer:          config.Host,
		//AudienceReader:  opts.AudienceReader,
		AudSecrets: opts.AudSecrets,
		SameSite:   opts.SameSiteCookie,
	})

	var authHandler AuthHandler

	if config.Type == AuthTypeRedirect {
		authHandler = NewRedirectAuthHandler(config.Host, config.SuccessRedirectUrl, credChecker, jwtService, storage)
	} else {
		authHandler = NewApiAuthHandler(config.Host, config.SuccessRedirectUrl, credChecker, jwtService, storage)
	}

	a = &Auth{
		config:      config,
		storage:     storage,
		authHandler: authHandler,
		jwtService:  jwtService,
	}

	return a
}

type TokenSenderFunc = func(email, token string) error

func (a *Auth) SetActivationTokenSender(senderFunc TokenSenderFunc) {
	a.authHandler.SetActivationTokenSender(senderFunc)
}

// Opts is a full set of all parameters to initialize Service
type Opts struct {
	SecretReader   token.Secret        // reader returns secret for given site id (aud), required
	ClaimsUpd      token.ClaimsUpdater // updater for jwt to add/modify values stored in the token
	SecureCookies  bool                // makes jwt cookie secure
	TokenDuration  time.Duration       // token's TTL, refreshed automatically
	CookieDuration time.Duration       // cookie's TTL. This cookie stores JWT token

	DisableXSRF bool // disable XSRF protection, useful for testing/debugging
	DisableIAT  bool // disable IssuedAt claim

	// optional (custom) names for cookies and headers
	JWTCookieName   string        // default "JWT"
	JWTCookieDomain string        // default empty
	JWTHeaderKey    string        // default "X-JWT"
	XSRFCookieName  string        // default "XSRF-TOKEN"
	XSRFHeaderKey   string        // default "X-XSRF-TOKEN"
	JWTQuery        string        // default "token"
	SendJWTHeader   bool          // if enabled send JWT as a header instead of cookie
	SameSiteCookie  http.SameSite // limit cross-origin requests with SameSite cookie attribute

	Issuer string // optional value for iss claim, usually the application name, default "n10ty/authless"

	URL       string          // root url for the rest service, i.e. http://blah.example.com, required
	Validator token.Validator // validator allows to reject some valid tokens with user-defined logic

	AudSecrets bool // allow multiple secrets (secret per aud)
	//Logger           logger.L                 // logger interface, default is no logging at all
	//RefreshCache     middleware.RefreshCache  // optional cache to keep refreshed tokens
}
