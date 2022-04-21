package authless

import (
	"fmt"
	authService "github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
	"github.com/spf13/viper"
	"net/http"
)

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