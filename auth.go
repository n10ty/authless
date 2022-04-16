package authless

import (
	_ "embed"
	"fmt"
	"net/http"
	"time"

	authService "github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"github.com/n10ty/authless/storage"
	"github.com/spf13/viper"
)

var a *Auth

const AuthTypeRedirect = "redirect"
const AuthTypeAPI = "api"

type Auth struct {
	storage *storage.Storage
	config  *Config
	auth    *authService.Service
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

func readConfig(path string) (*Config, error) {
	var cfg *Config
	viper.SetConfigFile(path)
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		return cfg, fmt.Errorf("Fatal error config file: %w \n", err)
	}

	err = viper.Unmarshal(&cfg)
	if err != nil {
		return cfg, fmt.Errorf("Fatal to read config file: %w \n", err)
	}

	return cfg, nil
}

func (cfg *Config) toLibCfg() authService.Opts {
	//TODO add config validation
	return authService.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			return cfg.Secret, nil
		}),
		SecureCookies:  true,
		DisableXSRF:    cfg.DisableXSRF,
		DisableIAT:     false,
		SameSiteCookie: http.SameSiteStrictMode,
		TokenDuration:  cfg.TokenDuration,
		CookieDuration: cfg.CookieDuration,
		Issuer:         cfg.AppName,
		URL:            "/",
		AvatarStore:    avatar.NewNoOp(),
		Validator: token.ValidatorFunc(func(_ string, claims token.Claims) bool {
			// allow only dev_* names
			//return claims.Email != nil && strings.HasPrefix(claims.Email.Name, "dev_")
			return true
		}),
		// TODO add logging
		//Logger: logger.New(logger.WithBody),
	}
}
