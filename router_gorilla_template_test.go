package authless_test

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/n10ty/authless"
	"github.com/n10ty/authless/storage"
	"github.com/n10ty/authless/token"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

const redirectURLGorilla = "http://localhost:8082"

var gorillaRedirectAuth authless.GorillaAuth

func teatRedirectGorillaUp() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)

	config := &authless.Config{
		Host:           "localhost",
		Secret:         "d123",
		DisableXSRF:    true,
		TokenDuration:  time.Minute,
		CookieDuration: time.Minute,
		Storage:        storage.Config{Type: storage.TypeInMemory, FileStoragePath: db},
		Type:           authless.AuthTypeTemplate,
		LogLevel:       "debug",
		TemplatePath:   "",
		Validator:      nil,
	}

	auth, err := authless.NewGorillaAuth(config)
	gorillaRedirectAuth = *auth
	if err != nil {
		log.Println(err)
		return
	}

	router := mux.NewRouter()

	gorillaRedirectAuth.InitServiceRoutes(router)

	router.Path("/private").Methods("GET").HandlerFunc(
		gorillaRedirectAuth.AuthRequired(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("private"))
		}),
	)
	router.Path("/user").Methods("GET").HandlerFunc(
		gorillaRedirectAuth.AuthRequired(
			func(w http.ResponseWriter, r *http.Request) {
				user, err := token.GetUserInfo(r)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				u, err := json.Marshal(user)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write(u)
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
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, redirectURLGorilla+"/login", url.String())
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURLGorilla, email, passw), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestChangePasswordNotFoundUserNotExecuted", func(t *testing.T) {
		exec := false
		gorillaRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(redirectURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestRegisterSuccess", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURLGorilla+"/auth/register", url.Values{"email": {email}, "password": {passw}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/success", url.String())
	})
	t.Run("TestChangePasswordNotActiveUserNotExecuted", func(t *testing.T) {
		exec := false
		gorillaRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(redirectURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestChangePasswordNotActiveUserReturnError", func(t *testing.T) {
		u := getUser(t, email)
		assert.NotEqual(t, u.ChangePasswordToken, "")
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/auth/change-password", redirectURLGorilla), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/change-password/result?error=Bad request", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestRegisterActivateFuncExecuted", func(t *testing.T) {
		exec := false
		gorillaRedirectAuth.SetActivationTokenSenderFunc(func(email, token string) error {
			exec = true
			return nil
		})
		http.PostForm(redirectURLGorilla+"/auth/register", url.Values{"email": {"v2@c.e"}, "password": {passw}})
		assert.True(t, exec)
	})
	t.Run("TestLoginNotEnabledRedirectToError", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURLGorilla, email, passw), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestActivateAccount", func(t *testing.T) {
		s, err := storage.NewInMemory(db)
		require.NoError(t, err)
		u, err := s.GetUser(email)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/activate?token=%s", redirectURLGorilla, u.ConfirmationToken), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/activate/result", url.String())
	})
	t.Run("TestLoginWrongPasswordRedirectError", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURLGorilla, email, "223"), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()

		cookies := resp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "JWT" {
				t.Errorf("Authenticated with wrong password")
			}
		}
		assert.Equal(t, redirectURLGorilla+"/login?error=Incorrect email or password", url.String())
	})
	t.Run("TestLoginSuccess", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/login?email=%s&password=%s", redirectURLGorilla, email, passw), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()

		cookies := resp.Cookies()

		for _, cookie := range cookies {
			if cookie.Name == "JWT" {
				jwtTok = cookie.Value
				return
			}
		}
		t.Error("Cookie not set")
		assert.Equal(t, redirectURLGorilla+"/", url.String())
	})
	t.Run("TestAccessPrivateAuthorized", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURLGorilla+"/private", nil)
		req.Header.Set("X-Jwt", jwtTok)
		c := http.DefaultClient
		resp, err := c.Do(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "private", string(body))
	})
	t.Run("TestAccessPrivateUserStatus", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, redirectURLGorilla+"/user", nil)
		req.Header.Set("X-Jwt", jwtTok)
		c := http.DefaultClient
		resp, err := c.Do(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"name\":\"a@a.a\",\"id\":\"d656370089fedbd4313c67bfdc24151fb7c0fe8b\"}", string(body))
	})
	t.Run("TestForgetPasswordWithEmptyEmailRedirectError", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURLGorilla+"/auth/forget-password", url.Values{"email": {"a."}})
		require.NoError(t, err)
		require.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/forget-password/result?error=Bad request", url.String())
	})
	t.Run("TestForgetPasswordRequestWithNotExistsUserIsOk", func(t *testing.T) {
		resp, err := httpClient.PostForm(redirectURLGorilla+"/auth/forget-password", url.Values{"email": {"a.22333@ddd.rrr"}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/forget-password/result", url.String())
	})
	t.Run("TestForgetPasswordExecuted", func(t *testing.T) {
		u := getUser(t, email)
		beforeToken := u.ChangePasswordToken

		exec := false
		gorillaRedirectAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			assert.Equal(t, "a@a.a", email)
			exec = true
			return nil
		})
		resp, err := httpClient.PostForm(redirectURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		assert.True(t, exec)

		u = getUser(t, email)
		afterToken := u.ChangePasswordToken
		assert.NotEqual(t, beforeToken, afterToken, "Token remain the same after change")
	})
	t.Run("TestChangePasswordUnexistsUserReturnOk", func(t *testing.T) {
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/auth/change-password", redirectURLGorilla), url.Values{"token": {"123"}, "password": {"newpassword"}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/change-password/result", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestChangePasswordSetPasswordSuccessfully", func(t *testing.T) {
		u := getUser(t, email)
		oldPasswordHash := u.Password
		resp, err := httpClient.PostForm(fmt.Sprintf("%s/auth/change-password", redirectURLGorilla), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		require.NoError(t, err)
		assert.Equal(t, 302, resp.StatusCode)
		url, err := resp.Location()
		assert.Equal(t, redirectURLGorilla+"/change-password/result", url.String())
		if resp.StatusCode != 302 {
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Error(string(body))
		}
		u = getUser(t, email)
		assert.NotEqual(t, oldPasswordHash, u.Password, "Password didn't changed")
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(passw))
		assert.ErrorIs(t, err, bcrypt.ErrMismatchedHashAndPassword)
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("newpassword"))
		require.NoError(t, err)
	})

	t.Run("TestChangePasswordPageExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/change-password", redirectURLGorilla), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestChangePasswordResultPageExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/change-password/result", redirectURLGorilla), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestForgetPasswordPageExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/forget-password", redirectURLGorilla), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestForgetPasswordResultPageExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/forget-password/result", redirectURLGorilla), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestActivateResultPageExists", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/activate/result", redirectURLGorilla), nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
}
