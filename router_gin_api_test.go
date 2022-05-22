package authless_test

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/n10ty/authless"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
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

var ginAPIAuth authless.GinAuth
var jwtTok string

func tearGinAPIUp() {
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
		Type:               authless.AuthTypeAPI,
		TemplatePath:       "",
		Validator:          nil,
		SuccessRedirectUrl: "",
	}

	auth, err := authless.NewGinAuth(config)
	ginAPIAuth = *auth
	if err != nil {
		log.Println(err)
		return
	}

	router := gin.Default()

	ginAPIAuth.InitServiceRoutes(router)

	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	router.Handle("GET", "/private", ginAPIAuth.AuthRequired(func(c *gin.Context) {
		c.String(200, "private")
	}))

	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	router.GET("/user", ginAPIAuth.AuthRequired(func(c *gin.Context) {
		user, err := token.GetUserInfo(c.Request)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.AbortWithStatusJSON(http.StatusOK, user)
	}))
	log.Fatal(http.ListenAndServe(":8080", router))
}

func tearGinAPIDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestRouterGinAPI(t *testing.T) {
	go tearGinAPIUp()
	defer tearGinAPIDown()
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
	t.Run("TestChangePasswordNotFoundUserNotExecuted", func(t *testing.T) {
		exec := false
		ginAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(URL+"/auth/change-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
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
	t.Run("TestChangePasswordNotActiveUserNotExecuted", func(t *testing.T) {
		exec := false
		ginAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(URL+"/auth/change-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestRegisterActivateFuncExecuted", func(t *testing.T) {
		exec := false
		ginAPIAuth.SetActivationTokenSenderFunc(func(email, token string) error {
			exec = true
			return nil
		})
		http.PostForm(URL+"/auth/register", url.Values{"email": {"v2@c.e"}, "password": {passw}})
		assert.True(t, exec)
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
		u := getUser(t, email)
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
	t.Run("TestChangePasswordExecuted", func(t *testing.T) {
		u := getUser(t, email)
		beforeToken := u.ChangePasswordToken
		exec := false
		ginAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			assert.Equal(t, "a@a.a", email)
			exec = true
			return nil
		})
		resp, err := http.PostForm(URL+"/auth/change-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, exec)

		u = getUser(t, email)
		afterToken := u.ChangePasswordToken
		assert.NotEqualf(t, beforeToken, afterToken, "Change password tokens are equals: %s", beforeToken)
	})
	t.Run("TestChangePasswordSetPasswordSuccessfully", func(t *testing.T) {
		u := getUser(t, email)
		oldPasswordHash := u.Password
		resp, err := http.PostForm(fmt.Sprintf("%s/auth/change-password", URL), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		if resp.StatusCode != 200 {
			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Error(string(body))
		}
		u = getUser(t, email)
		assert.NotEqual(t, oldPasswordHash, u.Password, "Password didn't changed")
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("newpassword"))
		assert.NoError(t, err)
	})
	t.Run("TestChangePasswordWithBadTokenReturnError", func(t *testing.T) {
		resp, err := http.PostForm(fmt.Sprintf("%s/auth/change-password", URL), url.Values{"token": {"badtoken"}, "password": {"newpassword"}})
		assert.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})
}

func getUser(t *testing.T, email string) *storage.User {
	s, err := storage.NewInMemory(db)
	assert.NoError(t, err)
	u, err := s.GetUser(email)
	assert.NoError(t, err)

	return u
}
