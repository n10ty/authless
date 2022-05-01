package authless_test

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/n10ty/authless"
	"github.com/n10ty/authless/storage"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const URL = "http://localhost:8080"
const email = "a@a.a"
const passw = "1234567"
const db = "db.txt"

var s storage.Storage
var jwtTok string

func teatApiUp() {
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
		Storage:            storage.Config{Type: storage.StorageTypeInMemory, FileStoragePath: db},
		Type:               authless.AuthTypeAPI,
		TemplatePath:       "",
		Validator:          nil,
		SuccessRedirectUrl: "",
	}

	auth, err := authless.NewGinAuth(config)
	if err != nil {
		log.Println(err)
		return
	}
	auth.SetTokenSender(func(email, token string) error {
		fmt.Println("TOKEN SEND", token)
		return nil
	})

	router := gin.Default()

	auth.InitServiceRoutes(router)

	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	router.Handle("GET", "/private", auth.AuthRequired(func(c *gin.Context) {
		c.String(200, "private")
	}))

	router.GET("/", func(c *gin.Context) {
		c.String(200, "index")
	})
	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	log.Fatal(http.ListenAndServe(":8080", router))
}

func tearDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestAPI(t *testing.T) {
	go teatApiUp()
	defer tearDown()
	time.Sleep(1 * time.Second)

	t.Run("TestAccessPrivateNotAuthorized", func(t *testing.T) {
		resp, err := http.Get(URL + "/private")
		assert.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "{\"error\":\"unauthorized\"}\n", string(body))
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", URL, email, passw))
		assert.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "{\"error\":\"incorrect email or password\"}\n", string(body))
	})
	t.Run("TestRegisterSuccess", func(t *testing.T) {
		resp, err := http.PostForm(URL+"/auth/register", url.Values{"email": {email}, "password": {passw}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		if resp.StatusCode != 200 {
			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestAccessPrivateNotAuthorized", func(t *testing.T) {
		resp, err := http.Get(URL + "/private")
		assert.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "{\"error\":\"unauthorized\"}\n", string(body))
	})
	t.Run("TestLoginDisabled", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", URL, email, passw))
		assert.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "{\"error\":\"incorrect email or password\"}\n", string(body))
	})
	t.Run("TestActivateAccount", func(t *testing.T) {
		s, err := storage.NewInMemory(db)
		assert.NoError(t, err)
		u, err := s.GetUser(email)
		assert.NoError(t, err)

		resp, err := http.Get(fmt.Sprintf("%s/auth/activate?token=%s", URL, u.ConfirmationToken))
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestLoginSuccess", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", URL, email, passw))
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.True(t, strings.Contains(string(body), "jwt"))
		assert.True(t, resp.Header.Get("X-Jwt") != "")
		jwtTok = resp.Header.Get("X-Jwt")
	})
	t.Run("TestAccessPrivateAuthorized", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, URL+"/private", nil)
		req.Header.Set("X-Jwt", jwtTok)
		c := http.DefaultClient
		resp, err := c.Do(req)
		assert.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "private", string(body))
	})
}
