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
	"testing"
	"time"
)

const redirectURL = "http://localhost:8081"

var ginRedirectAuth authless.GinAuth

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
		Type:               authless.AuthTypeTemplate,
		LogLevel:           "debug",
		TemplatePath:       "",
		Validator:          nil,
		SuccessRedirectUrl: "",
	}

	auth, err := authless.NewGinAuth(config)
	ginRedirectAuth = *auth
	if err != nil {
		log.Println(err)
		return
	}

	router := gin.Default()

	ginRedirectAuth.InitServiceRoutes(router)

	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	router.Handle("GET", "/private", ginRedirectAuth.AuthRequired(func(c *gin.Context) {
		c.String(200, "private")
	}))

	router.GET("/", func(c *gin.Context) {
		c.String(200, "public")
	})
	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	router.GET("/user", ginRedirectAuth.AuthRequired(func(c *gin.Context) {
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
		assert.NoError(t, err)
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
	t.Run("TestChangePasswordNotFoundUserNotExecuted", func(t *testing.T) {
		exec := false
		ginRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(redirectURL+"/auth/change-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestRegisterSuccess", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURL+"/auth/register", url.Values{"email": {email}, "password": {passw}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/success", url.String())
	})
	t.Run("TestChangePasswordNotActiveUserNotExecuted", func(t *testing.T) {
		exec := false
		ginRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(redirectURL+"/auth/change-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestChangePasswordNotActiveUserReturnError", func(t *testing.T) {
		u := getUser(t, email)
		assert.NotEqual(t, u.ChangePasswordToken, "")
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/auth/change-password", redirectURL), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/change-password/result?error=Bad request", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestRegisterActivateFuncExecuted", func(t *testing.T) {
		exec := false
		ginRedirectAuth.SetActivationTokenSenderFunc(func(email, token string) error {
			exec = true
			return nil
		})
		http.PostForm(redirectURL+"/auth/register", url.Values{"email": {"v2@c.e"}, "password": {passw}})
		assert.True(t, exec)
	})
	t.Run("TestLoginNotEnabledRedirectToError", func(t *testing.T) {
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
		assert.Equal(t, redirectURL+"/activate/result", url.String())
	})
	t.Run("TestLoginWrongPasswordRedirectError", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURL, email, "223"), nil)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()

		cookies := resp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "JWT" {
				t.Errorf("Authenticated with wrong password")
			}
		}
		assert.Equal(t, redirectURL+"/login?error=Incorrect email or password", url.String())
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
	t.Run("TestForgetPasswordWithEmptyEmailRedirectError", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURL+"/auth/forget-password/request", url.Values{"email": {"a."}})
		assert.NoError(t, err)
		assert.Equal(t, 301, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/forget-password/result?error=Bad request", url.String())
	})
	t.Run("TestForgetPasswordRequestWithNotExistsUserIsOk", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURL+"/auth/forget-password/request", url.Values{"email": {"a.22333@ddd.rrr"}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/forget-password/result", url.String())
	})
	t.Run("TestForgetPasswordExecuted", func(t *testing.T) {
		u := getUser(t, email)
		beforeToken := u.ChangePasswordToken

		exec := false
		ginRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			assert.Equal(t, "a@a.a", email)
			exec = true
			return nil
		})
		resp, err := httpClient.PostForm(redirectURL+"/auth/forget-password/request", url.Values{"email": {email}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		assert.True(t, exec)

		u = getUser(t, email)
		afterToken := u.ChangePasswordToken
		assert.NotEqual(t, beforeToken, afterToken, "Token remain the same after change")
	})
	t.Run("TestChangePasswordUnexistsUserReturnOk", func(t *testing.T) {
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/auth/change-password", redirectURL), url.Values{"token": {"123"}, "password": {"newpassword"}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/change-password/result", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestChangePasswordSetPasswordSuccessfully", func(t *testing.T) {
		u := getUser(t, email)
		oldPasswordHash := u.Password
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/change-password", redirectURL), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		assert.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURL+"/change-password/result", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Error(string(body))
		}
		u = getUser(t, email)
		assert.NotEqual(t, oldPasswordHash, u.Password, "Password didn't changed")
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(passw))
		assert.ErrorIs(t, err, bcrypt.ErrMismatchedHashAndPassword)
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("newpassword"))
		assert.NoError(t, err)
	})
}
