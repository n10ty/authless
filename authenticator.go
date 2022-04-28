package authless

import (
	"github.com/go-pkgz/auth/token"
	"github.com/pkg/errors"
	"log"
	"net/http"
)

type AuthHandler interface {
	LoginHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
	RegistrationHandler(w http.ResponseWriter, r *http.Request)
	ActivationHandler(w http.ResponseWriter, r *http.Request)
}

// auth implements all logic for authentication (reqAuth=true) and tracing (reqAuth=false)
func (a *Auth) doAuth(reqAuth bool) func(http.Handler) http.Handler {

	onError := func(h http.Handler, w http.ResponseWriter, r *http.Request, err error) {
		if !reqAuth { // if no auth required allow to proceeded on error
			h.ServeHTTP(w, r)
			return
		}
		log.Printf("[DEBUG] auth failed, %v", err)
		renderJsonError(w, "unauthorized", http.StatusUnauthorized)
	}

	f := func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			claims, tkn, err := a.jwtService.Get(r)
			if err != nil {
				onError(h, w, r, errors.Wrap(err, "can't get token"))
				return
			}

			if claims.Handshake != nil { // handshake in token indicate special use cases, not for login
				onError(h, w, r, errors.New("invalid kind of token"))
				return
			}

			if claims.User == nil {
				onError(h, w, r, errors.New("no user info presented in the claim"))
				return
			}

			if claims.User != nil { // if uinfo in token populate it to context
				// validator passed by client and performs check on token or/and claims
				if a.config.Validator != nil && !a.config.Validator.Validate(tkn, claims) {
					onError(h, w, r, errors.Errorf("user %s/%s blocked", claims.User.Name, claims.User.ID))
					a.jwtService.Reset(w)
					return
				}

				if a.jwtService.IsExpired(claims) {
					if claims, err = a.refreshExpiredToken(w, claims, tkn); err != nil {
						a.jwtService.Reset(w)
						onError(h, w, r, errors.Wrap(err, "can't refresh token"))
						return
					}
				}

				r = token.SetUserInfo(r, *claims.User) // populate user info to request context
			}

			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
	return f
}

// refreshExpiredToken makes a new token with passed claims
func (a *Auth) refreshExpiredToken(w http.ResponseWriter, claims token.Claims, tkn string) (token.Claims, error) {

	// cache refreshed claims for given token in order to eliminate multiple refreshes for concurrent requests
	//if a.RefreshCache != nil {
	//	if c, ok := a.RefreshCache.Get(tkn); ok {
	//		// already in cache
	//		return c.(token.Claims), nil
	//	}
	//}

	claims.ExpiresAt = 0                  // this will cause now+duration for refreshed token
	c, err := a.jwtService.Set(w, claims) // Set changes token
	if err != nil {
		return token.Claims{}, err
	}

	//if a.RefreshCache != nil {
	//	a.RefreshCache.Set(tkn, c)
	//}

	log.Printf("[DEBUG] token refreshed for %+v", claims.User)
	return c, nil
}
