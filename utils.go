package authless

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"regexp"
)

func passwordValid(password string) bool {
	return len(password) >= 6
}

func emailValid(email string) bool {
	r, _ := regexp.Compile("\\S+@\\S+\\.\\S+")

	return r.Match([]byte(email))
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "can't get random")
	}
	s := sha1.New()
	if _, err := s.Write(b); err != nil {
		return "", errors.Wrap(err, "can't write randoms to sha1")
	}
	return fmt.Sprintf("%x", s.Sum(nil)), nil
}

// JSON is a map alias, just for convenience
type JSON map[string]interface{}

// renderJSONWithStatus sends data as json and enforces status code
func renderJSONWithStatus(w http.ResponseWriter, data any, code int) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func renderJsonError(w http.ResponseWriter, msg string, code int) {
	j, _ := json.Marshal(JSON{"error": msg})
	http.Error(w, string(j), code)
}
