package authless_test

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/n10ty/authless"
	"github.com/n10ty/authless/storage"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
	"time"
)

const redirectURLGorilla = "http://localhost:8082"

func teatRedirectGorillaUp() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)

	config := &authless.Config{
		Host:               "localhost",
		Secret:             "d123",
		DisableXSRF:        true,
		TokenDuration:      time.Minute,
		CookieDuration:     time.Minute,
		Storage:            storage.Config{Type: storage.TypeInMemory, FileStoragePath: db},
		Type:               authless.AuthTypeTemplate,
		LogLevel:           "debug",
		TemplatePath:       "",
		Validator:          nil,
		SuccessRedirectUrl: "",
	}

	auth, err := authless.NewGorillaAuth(config)
	if err != nil {
		log.Println(err)
		return
	}
	auth.SetActivationTokenSenderFunc(func(email, token string) error {
		fmt.Println("TOKEN SEND", token)
		return nil
	})

	router := mux.NewRouter()

	auth.InitServiceRoutes(router)

	router.Path("/private").Methods("GET").HandlerFunc(
		auth.AuthRequired(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("private"))
		}),
	)

	log.Fatal(http.ListenAndServe(":8082", router))
}

func tearRedirectGorillaDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestRedirectGorilla(t *testing.T) {
	go teatRedirectGorillaUp()
	defer tearRedirectGorillaDown()
	time.Sleep(1 * time.Second)

	t.Run("TestAccessPrivateNotAuthorizedRedirectToLogin", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURLGorilla+"/private", nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/login", url.String())
	})
}
