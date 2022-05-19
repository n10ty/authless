package storage

import (
	"fmt"
	"log"
)

type Const struct {
	creds map[string]string
}

func NewConst(creds map[string]string) (*Const, error) {
	log.Printf("Loaded %d users\n", len(creds))
	return &Const{
		creds: creds,
	}, nil
}

func (f *Const) AuthenticateUser(email, password string) (bool, error) {
	if p, exists := f.creds[email]; exists {
		if p == password {
			return true, nil
		}
	}

	return false, nil
}

func (f *Const) GetUser(email string) (*User, error) {
	if _, exists := f.creds[email]; !exists {
		return &User{}, ErrUserNotFound
	}

	return NewUser(email, f.creds[email])
}

func (f *Const) GetUserByConfirmationToken(token string) (*User, error) {
	return nil, fmt.Errorf("not supported")
}

func (f *Const) CreateUser(user *User) error {
	panic("can't create user")
}

func (f *Const) UpdateUser(user *User) error {
	panic("Can't update user")
}
