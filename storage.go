package authless

import (
	"errors"
)

type storageType = string

const storageTypeMysql = "mysql"
const storageTypePostgres = "postgres"
const storageTypeCloud = "cloud"

var ErrUserNotFound = errors.New("user not found")

type Storage interface {
	AuthenticateUser(user, password string) (bool, error)
	CreateUser(user *User) error
	GetUser(email string) (*User, error)
}

type StorageConfig struct {
	Type     storageType
	Host     string
	Port     int
	Username string
	Password string
	Dbname   string
}

func NewStorage(config StorageConfig) (Storage, error) {
	//var storage *Storage
	switch config.Type {
	case storageTypeMysql:
		return NewMysqlStorage(config)
	default:
		return nil, errors.New("Unknown storage type: " + config.Type)
	}
}
