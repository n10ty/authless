package authless

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"time"
)

func passwordValid(password string) bool {
	return len(password) >= 6
}

func emailValid(email string) bool {
	r, _ := regexp.Compile("\\S+@\\S+\\.\\S+")

	return r.Match([]byte(email))
}

func RandToken(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)

	return fmt.Sprintf("%x", b)[:length]
}

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
