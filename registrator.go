package authless

import (
	"errors"
	"log"
	"regexp"

	"github.com/n10ty/authless/storage"
)

func (a *Auth) register(email, password string) error {
	if !passwordValid(password) {
		return errors.New("Password must be contains at least 6 symbols")
	}

	if !emailValid(email) {
		return errors.New("Invalid email")
	}

	_, err := (*a.storage).GetUser(email)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Printf("internal error: %s", err)
		return errors.New("Internal error")
	}

	user, err := storage.NewUser(email, password)
	if err != nil {
		log.Printf("internal error: %s", err)
		return errors.New("Internal error")
	}

	if a.tokenSenderFunc == nil {
		user.Enabled = true
	} else {
		if err := a.tokenSenderFunc(user.ConfirmationToken); err != nil {
			log.Printf("Error during send confirmation token: %s\n", err.Error())
			return errors.New("Internal error")
		}
	}

	err = (*a.storage).CreateUser(user)
	if err != nil {
		log.Printf("internal error: %s", err)
		return errors.New("Internal error")
	}

	return nil
}

func passwordValid(password string) bool {
	return len(password) >= 6
}

func emailValid(email string) bool {
	r, _ := regexp.Compile("\\S+@\\S+\\.\\S+")

	return r.Match([]byte(email))
}
