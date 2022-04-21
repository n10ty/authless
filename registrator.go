package authless

import (
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/n10ty/authless/storage"
)

func (a *Auth) register(w http.ResponseWriter, r *http.Request) {
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

	_, err := (*a.storage).GetUser(email)
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

	if a.tokenSenderFunc == nil {
		user.Enabled = true
	} else {
		if err := a.tokenSenderFunc(user.ConfirmationToken); err != nil {
			log.Printf("Error during send confirmation token: %s\n", err.Error())
			http.Redirect(w, r, "/register?error=Internal error", http.StatusMovedPermanently)
			return
		}
	}

	err = (*a.storage).CreateUser(user)
	if err != nil {
		log.Printf("internal error: %s", err)
		http.Redirect(w, r, "/register?error=Internal error", http.StatusMovedPermanently)
		return
	}

	http.Redirect(w, r, "/success", http.StatusFound)
}

func passwordValid(password string) bool {
	return len(password) >= 6
}

func emailValid(email string) bool {
	r, _ := regexp.Compile("\\S+@\\S+\\.\\S+")

	return r.Match([]byte(email))
}
