package storage

import (
	"errors"
)

type storageType = string

const (
	storageTypeMysql    = "mysql"
	storageTypePostgres = "postgres"
	storageTypeCloud    = "cloud"
	storageTypeConst    = "const"
	storageTypeInMemory = "inmemory"
)

var ErrUserNotFound = errors.New("user not found")

type Storage interface {
	AuthenticateUser(email, password string) (bool, error)
	CreateUser(user *User) error
	GetUser(email string) (*User, error)
	GetUserByToken(token string) (*User, error)
	UpdateUser(user *User) error
}

type Config struct {
	Type            storageType
	FileStoragePath string
	Host            string
	Port            int
	Username        string
	Password        string
	Dbname          string
	Users           map[string]string
}

func NewStorage(config Config) (Storage, error) {
	//var storage *Storage
	switch config.Type {
	case storageTypeMysql:
		return NewMysqlStorage(config)
	case storageTypeConst:
		// todo read from config
		return NewConst(config.Users)
	case storageTypeInMemory:
		return NewInMemory(config.FileStoragePath)
	default:
		return nil, errors.New("Unknown storage type: " + config.Type)
	}
}
