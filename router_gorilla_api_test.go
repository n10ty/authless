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
	"strings"
	"testing"
	"time"
)

const apiURLGorilla = "http://localhost:8083"

var gorillaAPIAuth authless.GorillaAuth

func tearAPIGorillaUp() {
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
		Type:           authless.AuthTypeAPI,
		LogLevel:       "debug",
		TemplatePath:   "",
		Validator:      nil,
	}

	auth, err := authless.NewGorillaAuth(config)
	gorillaAPIAuth = *auth
	if err != nil {
		log.Println(err)
		return
	}

	router := mux.NewRouter()

	gorillaAPIAuth.InitServiceRoutes(router)

	router.Path("/private").Methods("GET").HandlerFunc(
		gorillaAPIAuth.AuthRequired(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("private"))
		}),
	)
	router.Path("/user").Methods("GET").HandlerFunc(
		gorillaAPIAuth.AuthRequired(
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

	log.Fatal(http.ListenAndServe(":8083", router))
}

func tearGorillaAPIDown() {
	log.Println("[DEBUG] Stop server")
	os.Truncate(db, 0)
}

func TestRouterGorillaAPI(t *testing.T) {
	go tearAPIGorillaUp()
	defer tearGorillaAPIDown()
	time.Sleep(1 * time.Second)

	t.Run("TestAccessPrivateNotAuthorized", func(t *testing.T) {
		resp, err := http.Get(apiURLGorilla + "/private")
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"error\":\"unauthorized\"}\n", string(body))
	})
	t.Run("TestLoginUserNotExists", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", apiURLGorilla, email, passw))
		require.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"error\":\"incorrect email or password\"}\n", string(body))
	})
	t.Run("TestRegisterShortPasswordError", func(t *testing.T) {
		resp, err := http.PostForm(apiURLGorilla+"/auth/register", url.Values{"email": {email}, "password": {"1"}})
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.JSONEq(t, `{"error":"password must be contains at least 6 symbols"}`, string(body))
	})
	t.Run("TestInvalidEmailError", func(t *testing.T) {
		resp, err := http.PostForm(apiURLGorilla+"/auth/register", url.Values{"email": {"233"}, "password": {passw}})
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		assert.JSONEq(t, `{"error":"invalid email"}`, string(body))
	})
	t.Run("TestChangePasswordNotFoundUserNotExecuted", func(t *testing.T) {
		exec := false
		gorillaAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(apiURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestRegisterSuccess", func(t *testing.T) {
		resp, err := http.PostForm(apiURLGorilla+"/auth/register", url.Values{"email": {email}, "password": {passw}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		if resp.StatusCode != 200 {
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Error(string(body))
		}
	})
	t.Run("TestChangePasswordNotActiveUserNotExecuted", func(t *testing.T) {
		exec := false
		gorillaAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			exec = true
			return nil
		})
		resp, err := http.PostForm(apiURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, exec)
	})
	t.Run("TestRegisterActivateFuncExecuted", func(t *testing.T) {
		exec := false
		gorillaAPIAuth.SetActivationTokenSenderFunc(func(email, token string) error {
			exec = true
			return nil
		})
		http.PostForm(apiURLGorilla+"/auth/register", url.Values{"email": {"v2@c.e"}, "password": {passw}})
		assert.True(t, exec)
	})
	t.Run("TestAccessPrivateNotAuthorized", func(t *testing.T) {
		resp, err := http.Get(apiURLGorilla + "/private")
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"error\":\"unauthorized\"}\n", string(body))
	})
	t.Run("TestLoginDisabled", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", apiURLGorilla, email, passw))
		require.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"error\":\"incorrect email or password\"}\n", string(body))
	})
	t.Run("TestActivateAccount", func(t *testing.T) {
		u := getUser(t, email)
		resp, err := http.Get(fmt.Sprintf("%s/auth/activate?token=%s", apiURLGorilla, u.ConfirmationToken))
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	t.Run("TestLoginSuccess", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/auth/login?email=%s&password=%s", apiURLGorilla, email, passw))
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

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
		req, _ := http.NewRequest(http.MethodGet, apiURLGorilla+"/private", nil)
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
		req, _ := http.NewRequest(http.MethodGet, apiURLGorilla+"/user", nil)
		req.Header.Set("X-Jwt", jwtTok)
		c := http.DefaultClient
		resp, err := c.Do(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, "{\"name\":\"a@a.a\",\"id\":\"d656370089fedbd4313c67bfdc24151fb7c0fe8b\"}", string(body))
	})
	t.Run("TestChangePasswordExecuted", func(t *testing.T) {
		u := getUser(t, email)
		beforeToken := u.ChangePasswordToken
		exec := false
		gorillaAPIAuth.SetChangePasswordRequestFunc(func(email, token string) error {
			assert.Equal(t, "a@a.a", email)
			exec = true
			return nil
		})
		resp, err := http.PostForm(apiURLGorilla+"/auth/forget-password", url.Values{"email": {email}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, exec)

		u = getUser(t, email)
		afterToken := u.ChangePasswordToken
		assert.NotEqualf(t, beforeToken, afterToken, "Change password tokens are equals: %s", beforeToken)
	})
	t.Run("TestChangePasswordSetPasswordSuccessfully", func(t *testing.T) {
		u := getUser(t, email)
		oldPasswordHash := u.Password
		resp, err := http.PostForm(fmt.Sprintf("%s/auth/change-password", apiURLGorilla), url.Values{"token": {u.ChangePasswordToken}, "password": {"newpassword"}})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		if resp.StatusCode != 200 {
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Error(string(body))
		}
		u = getUser(t, email)
		assert.NotEqual(t, oldPasswordHash, u.Password, "Password didn't changed")
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("newpassword"))
		require.NoError(t, err)
	})
	t.Run("TestChangePasswordWithBadTokenReturnError", func(t *testing.T) {
		resp, err := http.PostForm(fmt.Sprintf("%s/auth/change-password", apiURLGorilla), url.Values{"token": {"badtoken"}, "password": {"newpassword"}})
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})
}
