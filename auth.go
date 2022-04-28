package authless

import (
	_ "embed"
	"time"

	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"github.com/n10ty/authless/storage"
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
	//credChecker     provider.CredChecker
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

	a = newAuth(config, storage)

	return nil
}

func newAuth(config *Config, storage storage.Storage) *Auth {

	opts := config.toLibCfg()

	credChecker := provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
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
		AudienceReader:  opts.AudienceReader,
		AudSecrets:      opts.AudSecrets,
		SameSite:        opts.SameSiteCookie,
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

type Config struct {
	Host               string
	Secret             string
	DisableXSRF        bool
	TokenDuration      time.Duration
	CookieDuration     time.Duration
	Storage            storage.Config
	Type               string // redirect or api
	TemplatePath       string
	Validator          token.Validator
	SuccessRedirectUrl string
}

type TokenSenderFunc = func(email, token string) error

func (a *Auth) SetActivationTokenSender(senderFunc TokenSenderFunc) {
	a.tokenSenderFunc = senderFunc
}
