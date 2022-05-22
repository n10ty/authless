# Authless - easy setup user authentication lib 

This library provide user login/registration feature based
on cookie JWT token with multiple storage support. 

* Registration
* Login
* JWT token via cookie
* Some custom html templates read to use
* Or use it only as a backend with your own frontend
* Confirmation token
* Multiple router supports (Gin, standard, etc.)
* Multiple storage supports (Mysql, Postgres, config, "create your own", ...)

## Getting started
With Gin: 
``` go
func main() {
	configPath := "./default.yml"
	auth, err := authless.NewGinAuth(configPath)
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

	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Config

```yaml
appName: myapp.com // your domain
secret: mysecret // generate random secret
disablexsrf: false
type: redirect // 'redirect' or 'api'
storage:
  type: mysql  // mysql, const (setup by config), postgres
  host: localhost
  port: 3306
  username: root
  password: 12345
  dbname: test_auth
```

## HTML templates

There are ready to use html login/registration forms. To use it
copy `template` folder to your project root.

![Image](/login-form.png)

## Routes

### Login
Call GET ```/auth/login?email=test@example.com&passwd=xyz```
or send POST form
```json
{
    "email": "test@example.com",
    "password": "xyz"
}
```

### Logout
Call GET `/auth/logout` to remove cookie and blacklist token (see todo)

### Register
Send POST form ```/auth/register```
```json
{
    "email": "test@example.com",
    "password": "xyz"
}
```
to create new user. Created user is not active and unable to login.

#### Send activation token

Use `TokenSenderFunc = func(email, token string) error` to send token during registration
Example: 
```go
auth, _ := authless.NewGinAuth(configPath)
client := NewMailerClient(somekey)
auth.SetTokenSender(func(email, token string) error {
    return client.SendEmail(email, token)
})
```

### Activate
Call GET ```/auth/activate?token=mytoken```
to activate account to able account to login

Todo:

- [x] Add tests
- [x] Add gorilla http router
- [x] Add default http router
- [ ] Forget password
- [x] Get rid of /r/
- [x] Add global auth.GetUser method
- [x] Fully get rid of authz package
- [ ] Load default html template
- [ ] Validate html present
- [ ] Finish README
- [ ] Add postgres
- [ ] Validate config
- [ ] Pass full url to forget pass/validate acc functions
- [ ] Blacklist of expired tokens (after logout token invalid)
- [ ] Get rid of error message in query ?error=bad request