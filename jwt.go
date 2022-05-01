package authless

import "github.com/n10ty/authless/token"

// ValidatorFunc type is an adapter to allow the use of ordinary functions as Validator. If f is a function
// with the appropriate signature, ValidatorFunc(f) is a Validator that calls f.
type ValidatorFunc func(token string, claims token.Claims) bool

// Validate calls f(id)
func (f ValidatorFunc) Validate(token string, claims token.Claims) bool {
	return f(token, claims)
}

// SecretFunc type is an adapter to allow the use of ordinary functions as Secret. If f is a function
// with the appropriate signature, SecretFunc(f) is a Handler that calls f.
type SecretFunc func(aud string) (string, error)

// Get calls f()
func (f SecretFunc) Get(aud string) (string, error) {
	return f(aud)
}
