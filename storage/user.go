package storage

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const cost = bcrypt.DefaultCost

type User struct {
	Id                int64     `db:"id"`
	Email             string    `db:"email"`
	Enabled           bool      `db:"enabled"`
	Password          string    `db:"password"`
	LastLoginDate     time.Time `db:"last_login_date"`
	ConfirmationToken string    `db:"confirmation_token"`
	plainPassword     string
}

func NewUser(email string, plainPassword string) (*User, error) {
	password, err := EncryptPassword(plainPassword)
	if err != nil {
		return nil, err
	}

	return &User{
		Email:             email,
		Enabled:           true,
		plainPassword:     plainPassword,
		Password:          password,
		ConfirmationToken: GenerateConfirmationToken(),
	}, nil
}

func EncryptPassword(plainPassword string) (string, error) {
	if plainPassword == "" {
		return "", errors.New("password can not be empty")
	}

	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(plainPassword), cost)
	if err != nil {
		return "", errors.New("internal error")
	}

	return string(passwordBytes), nil
}

func GenerateConfirmationToken() string {
	length := 64
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)

	return fmt.Sprintf("%x", b)[:length]
}
