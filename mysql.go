package authless

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

type MysqlStorage struct {
	db *sqlx.DB
}

//type MysqlConfig struct {
//	Host     string
//	Port     int
//	Email     string
//	Password string
//	Dbname   string
//}

func NewMysqlStorage(config StorageConfig) (*MysqlStorage, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8&parseTime=True&loc=Local",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Dbname,
	)
	db, err := sqlx.Connect("mysql", dsn)

	return &MysqlStorage{db: db}, err
}

func (s *MysqlStorage) AuthenticateUser(email, password string) (bool, error) {
	u, err := s.GetUser(email)
	if err != nil && errors.Is(err, ErrUserNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		return false, errors.New("wrong password")
	}

	return true, nil
}

func (s *MysqlStorage) CreateUser(user *User) error {
	_, err := s.db.NamedExec(`INSERT INTO users (email, password, registration_date, confirmation_token) VALUES (:email, :password, now(), :confirmation_token)`, *user)
	if err != nil {
		return errors.New("error during creating user")
	}

	return nil
}

func (s *MysqlStorage) GetUser(email string) (*User, error) {
	user := &User{}
	err := s.db.Get(user, "SELECT id, email, enabled, password, confirmation_token FROM users WHERE email = ?", email)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return user, ErrUserNotFound
	}

	return user, nil
}
