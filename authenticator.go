package authless

import (
	"errors"
	"fmt"
	"github.com/n10ty/authless/token"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// CredCheckerFunc type is an adapter to allow the use of ordinary functions as CredsChecker.
type CredCheckerFunc func(user, password string) (ok bool, err error)

// Check calls f(user,passwd)
func (f CredCheckerFunc) Check(user, password string) (ok bool, err error) {
	return f(user, password)
}

type AuthHandler interface {
	LoginHandler(http.ResponseWriter, *http.Request)
	LogoutHandler(http.ResponseWriter, *http.Request)
	RegistrationHandler(http.ResponseWriter, *http.Request)
	ActivationHandler(http.ResponseWriter, *http.Request)
	SetActivationTokenSenderFunc(TokenSenderFunc)
	ChangePasswordRequestHandler(http.ResponseWriter, *http.Request)
	SetChangePasswordRequestFunc(ChangePasswordRequestFunc)
	ChangePasswordHandler(http.ResponseWriter, *http.Request)
}

// doAuth implements all logic for authentication (reqAuth=true) and tracing (reqAuth=false)
func doAuth(redirect bool, w http.ResponseWriter, r *http.Request) {
	onError := func(w http.ResponseWriter, r *http.Request, err error) {
		_, err = token.GetUserInfo(r)
		if err != nil {
			if redirect {
				http.Redirect(w, r, "/login", http.StatusFound)
			} else {
				renderJsonError(w, "unauthorized", http.StatusUnauthorized)
			}
			return

		}
		log.Debugf("Could not authorize: %s", err)
	}

	claims, tkn, err := a.jwtService.Get(r)
	if err != nil {
		onError(w, r, fmt.Errorf("can't get token: %w", err))
		return
	}

	if claims.Handshake != nil { // handshake in token indicate special use cases, not for login
		onError(w, r, errors.New("invalid kind of token"))
		return
	}

	if claims.User == nil {
		onError(w, r, errors.New("no user info presented in the claim"))
		return
	}

	if claims.User != nil { // if uinfo in token populate it to context
		// validator passed by client and performs check on token or/and claims
		if a.config.Validator != nil && !a.config.Validator.Validate(tkn, claims) {
			onError(w, r, fmt.Errorf("user %s/%s blocked", claims.User.Name, claims.User.ID))
			a.jwtService.Reset(w)
			return
		}

		if a.jwtService.IsExpired(claims) {
			if claims, err = a.refreshExpiredToken(w, claims, tkn); err != nil {
				a.jwtService.Reset(w)
				onError(w, r, fmt.Errorf("can't refresh token: %w", err))
				return
			}
		}

		token.SetUserInfo(r, *claims.User) // populate user info to request context
		fmt.Println(r.URL)
	}
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
