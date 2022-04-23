package authless

import (
	"errors"
	"github.com/n10ty/authless/storage"
	"log"
)

func (a *Auth) activate(token string) error {
	if token == "" {
		return errors.New("Bad token")
	}

	user, err := (*a.storage).GetUserByToken(token)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Printf("internal error: %s", err)
		return errors.New("Internal error")
	} else if errors.Is(err, storage.ErrUserNotFound) {
		return errors.New("Bad token")
	}

	if user.ConfirmationToken != token {
		return errors.New("Bad token")
	}

	user.Enabled = true
	if err := (*a.storage).UpdateUser(user); err != nil {
		log.Printf("internal error: %s", err)
		return errors.New("Internal error")
	}

	return nil
}
