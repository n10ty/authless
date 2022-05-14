package authless_test

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/n10ty/authless"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
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
	router.GET("/user", auth.AuthRequired(func(c *gin.Context) {
		user, err := token.GetUserInfo(c.Request)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.AbortWithStatusJSON(http.StatusOK, user)
	}))
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
	t.Run("TestRegisterShortPasswordError", func(t *testing.T) {
		resp, err := http.PostForm(URL+"/auth/register", url.Values{"email": {email}, "password": {"1"}})
		assert.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.JSONEq(t, `{"error":"password must be contains at least 6 symbols"}`, string(body))
	})
	t.Run("TestInvalidEmailError", func(t *testing.T) {
		resp, err := http.PostForm(URL+"/auth/register", url.Values{"email": {"233"}, "password": {passw}})
		assert.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.JSONEq(t, `{"error":"invalid email"}`, string(body))
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

		assert.True(t, strings.Contains(string(body), "jwt"), "Response does not contains jwt token")
		cookies := resp.Cookies()

		for _, cookie := range cookies {
			if cookie.Name == "JWT" {
				jwtTok = cookie.Value
				return
			}
		}
		t.Error("Cookie not set")
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
	t.Run("TestAccessPrivateUserStatus", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, URL+"/user", nil)
		req.Header.Set("X-Jwt", jwtTok)
		c := http.DefaultClient
		resp, err := c.Do(req)
		assert.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "{\"name\":\"a@a.a\",\"id\":\"d656370089fedbd4313c67bfdc24151fb7c0fe8b\"}", string(body))
	})
}
