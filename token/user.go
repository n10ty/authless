package token

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc64"
	"io"
	"net/http"
	"regexp"
)

var reValidSha = regexp.MustCompile("^[a-fA-F0-9]{40}$")
var reValidCrc64 = regexp.MustCompile("^[a-fA-F0-9]{16}$")

// User is the basic part of oauth data provided by service
type User struct {
	// set by service
	Name     string `json:"name"`
	ID       string `json:"id"`
	Audience string `json:"aud,omitempty"`

	// set by client
	IP         string                 `json:"ip,omitempty"`
	Email      string                 `json:"email,omitempty"`
	Attributes map[string]interface{} `json:"attrs,omitempty"`
	Role       string                 `json:"role,omitempty"`
}

// HashID tries to hash val with hash.Hash and fallback to crc if needed
func HashID(h hash.Hash, val string) string {

	if reValidSha.MatchString(val) {
		return val // already hashed or empty
	}

	if _, err := io.WriteString(h, val); err != nil {
		// fail back to crc64
		if val == "" {
			val = "!empty string!"
		}
		if reValidCrc64.MatchString(val) {
			return val // already crced
		}
		return fmt.Sprintf("%x", crc64.Checksum([]byte(val), crc64.MakeTable(crc64.ECMA)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type contextKey string

// MustGetUserInfo gets user info and panics if can't extract it from the request.
// should be called from authenticated controllers only
func MustGetUserInfo(r *http.Request) User {
	user, err := GetUserInfo(r)
	if err != nil {
		panic(err)
	}
	return user
}

// GetUserInfo returns user info from request context
func GetUserInfo(r *http.Request) (user User, err error) {

	ctx := r.Context()
	if ctx == nil {
		return User{}, errors.New("no info about user")
	}
	if u, ok := ctx.Value(contextKey("user")).(User); ok {
		return u, nil
	}

	return User{}, errors.New("user can't be parsed")
}

// SetUserInfo sets user into request context
func SetUserInfo(r *http.Request, user User) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, contextKey("user"), user)

	*r = *r.Clone(ctx)
}
