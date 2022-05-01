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
	"testing"
	"time"
)

const redirectURL = "http://localhost:8081"

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func teatRedirectUp() {
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
		Type:               authless.AuthTypeRedirect,
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
		c.String(200, "public")
	})
	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	stop := make(chan interface{})
	log.Fatal(http.ListenAndServe(":8081", router))
	<-stop
}

func tearRedirectDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestRedirect(t *testing.T) {
	go teatRedirectUp()
	defer tearRedirectDown()
	time.Sleep(1 * time.Second)

	t.Run("TestAccessPrivateNotAuthorizedRedirectToLogin", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURL+"/private", nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/login", url.String())
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, passw), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, passw), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestRegisterSuccess", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURL+"/auth/register", url.Values{"email": {email}, "password": {passw}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/success", url.String())
	})
	t.Run("TestLoginNotEnabledRedirectToLogin", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, passw), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestActivateAccount", func(t *testing.T) {
		s, err := storage.NewInMemory(db)
		assert.NoError(t, err)
		u, err := s.GetUser(email)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/activate?token=%s", redirectURL, u.ConfirmationToken), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/activate-result", url.String())
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, passw), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 301, resp.StatusCode)
		url, err := resp.Location()
		jwtTok = resp.Header.Get("X-Jwt")
		assert.True(t, len(jwtTok) > 65)
		assert.Equal(t, redirectURL+"/", url.String())
	})
	t.Run("TestAccessPrivateAuthorized", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURL+"/private", nil)
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
