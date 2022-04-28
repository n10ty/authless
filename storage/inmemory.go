package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

type InMemory struct {
	users  map[string]User
	tokens map[string]User
	f      *os.File
}

func NewInMemory(path string) (*InMemory, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 777)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(f)
	var u User
	inmemory := &InMemory{
		users:  make(map[string]User, 10),
		tokens: make(map[string]User, 10),
		f:      f,
	}

	for scanner.Scan() {
		t := scanner.Text()
		fmt.Println(t)
		err := json.Unmarshal([]byte(t), &u)
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
		inmemory.tokens[u.ConfirmationToken] = u
		inmemory.users[u.Email] = u
	}

	return inmemory, nil
}

func (m *InMemory) AuthenticateUser(email, password string) (bool, error) {
	if u, exists := m.users[email]; exists {
		err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
		if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("[ERROR] internal error: %s\n", err)
			return false, errors.New("internal error")
		} else if err == nil && errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return u.Enabled, nil
	}

	return false, nil
}

func (m *InMemory) GetUser(email string) (*User, error) {
	if user, exists := m.users[email]; !exists {
		return &User{}, ErrUserNotFound
	} else {
		return &user, nil
	}
}

func (m *InMemory) GetUserByToken(token string) (*User, error) {
	if user, exists := m.tokens[token]; !exists {
		return &User{}, ErrUserNotFound
	} else {
		return &user, nil
	}
}

func (m *InMemory) CreateUser(user *User) error {
	m.tokens[user.ConfirmationToken] = *user
	m.users[user.Email] = *user

	m.sync()
	return nil
}

func (m *InMemory) UpdateUser(user *User) error {
	return m.CreateUser(user)
}

func (m *InMemory) sync() error {
	m.f.Truncate(0)
	m.f.Seek(0, 0)
	for _, user := range m.users {
		u, _ := json.Marshal(user)
		fmt.Fprintf(m.f, "%s\n", u)
	}

	return m.f.Sync()
}
