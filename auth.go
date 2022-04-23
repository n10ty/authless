package authless

import (
	_ "embed"
	"time"

	authService "github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"github.com/n10ty/authless/storage"
)

var a *Auth

const AuthTypeRedirect = "redirect"
const AuthTypeAPI = "api"

type Auth struct {
	storage         *storage.Storage
	config          *Config
	auth            *authService.Service
	tokenSenderFunc TokenSenderFunc
}

func initAuth(configPath string) error {
	config, err := readConfig(configPath)
	if err != nil {
		return err
	}
	storage, err := storage.NewStorage(config.Storage)
	if err != nil {
		return err
	}

	auth := newAuthService(config, &storage)
	a = &Auth{
		config:  config,
		storage: &storage,
		auth:    auth,
	}
	return nil
}

type Config struct {
	AppName        string
	Secret         string
	DisableXSRF    bool
	TokenDuration  time.Duration
	CookieDuration time.Duration
	Storage        storage.Config
	Type           string // redirect or api
}

func newAuthService(config *Config, storage *storage.Storage) *authService.Service {
	opts := config.toLibCfg()
	a := authService.NewService(opts)

	credChecker := provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
		return (*storage).AuthenticateUser(user, password)
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
		Issuer:          config.AppName,
		AudienceReader:  opts.AudienceReader,
		AudSecrets:      opts.AudSecrets,
		SameSite:        opts.SameSiteCookie,
	})

	var handler provider.Provider
	if config.Type == AuthTypeRedirect {
		handler = RedirectAuthHandler{
			CredChecker:  credChecker,
			TokenService: jwtService,
		}
	} else {
		handler = ApiAuthHandler{
			CredChecker:  credChecker,
			TokenService: jwtService,
		}
	}
	a.AddCustomHandler(handler)

	return a
}

type TokenSenderFunc = func(email, token string) error

func (a *Auth) SetTokenSender(senderFunc TokenSenderFunc) {
	a.tokenSenderFunc = senderFunc
}
