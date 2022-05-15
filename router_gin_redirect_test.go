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
	"testing"
	"time"
)

const redirectURL = "http://localhost:8081"

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func tearGinRedirectUp() {
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
		Type:               authless.AuthTypeRedirect,
		LogLevel:           "debug",
		TemplatePath:       "",
		Validator:          nil,
		SuccessRedirectUrl: "",
	}

	auth, err := authless.NewGinAuth(config)
	if err != nil {
		log.Println(err)
		return
	}

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
	router.GET("/user", auth.AuthRequired(func(c *gin.Context) {
		user, err := token.GetUserInfo(c.Request)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.AbortWithStatusJSON(http.StatusOK, user)
	}))
	log.Fatal(http.ListenAndServe(":8081", router))
}

func tearGinRedirectDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestRouterRedirectGin(t *testing.T) {
	go tearGinRedirectUp()
	defer tearGinRedirectDown()
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
	t.Run("TestRegisterActivateFuncExecuted", func(t *testing.T) {
		exec := false
		ginRedirectAuth.SetActivationTokenSender(func(email, token string) error {
			exec = true
			return nil
		})
		http.PostForm(redirectURL+"/auth/register", url.Values{"email": {"v2@c.e"}, "password": {passw}})
		assert.True(t, exec)
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
	t.Run("TestLoginSuccess", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, passw), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 301, resp.StatusCode)
		url, err := resp.Location()

		cookies := resp.Cookies()

		for _, cookie := range cookies {
			if cookie.Name == "JWT" {
				jwtTok = cookie.Value
				return
			}
		}
		t.Error("Cookie not set")
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
	t.Run("TestAccessPrivateUserStatus", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURL+"/user", nil)
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
