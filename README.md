# Authless - easy setup user authentication lib 

This library provide user login/registration feature based
on cookie JWT token with multiple storage support. 

* Registration
* Login
* JWT token via cookie
* Out of the box HTML templates read to use
* Or use it only as a backend with your own frontend
* Confirmation token
* Multiple router supports (Gin, standard, etc.)
* Multiple storage supports (Mysql, Postgres, config, "create your own", ...)

## Fast start
With Gin ([Routers](#Routers)):
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

#### Config

```yaml
appName: myapp.com // your domain
secret: mysecret // generate random secret
disablexsrf: false
type: html // 'html' or 'api'
storage:
  type: mysql  // mysql, const (setup by config), postgres
  host: localhost
  port: 3306
  username: root
  password: 12345
  dbname: test_auth
```

#### HTML templates

There are ready to use html login/registration forms. To use it
copy `template` folder to your project root.

![Image](/login-form.png)

## API Routes

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

Use `ActivateAccountFunc = func(email, url, token string) error` to send token during registration

Example: 
```go
auth, _ := authless.NewGinAuth(configPath)
client := NewMailerClient(somekey)
auth.SetActivationTokenSenderFunc(func(email, activateUrl, token string) error {
    //make user go to activateUrl to activate accoung
    return client.SendEmail(email, token)
})
```

### Activate
Call GET ```/auth/activate?token=mytoken```
to activate account to able account to login

### Forget password
To send change password send POST form to ```/auth/forget-password```:

    {
        "email": "test@example.com",
    }
This will generate new token and execute `ChangePasswordRequestFunc`

#### Send change password token
Use:

`type ChangePasswordRequestFunc = func(email, token string) error`

Example:
```go
auth, _ := authless.NewGinAuth(configPath)
client := NewMailerClient(somekey)
auth.SetChangePasswordRequestFunc(func(email, url, token string) error {
    return client.SendChangePassword
})
```

### Change password
To change password send POST form to `/auth/change-password`

    {
        "email": "test@example.com",
        "token": "TOKEN", //TOKEN sent by ChangePasswordRequestFunc
        "password": "newpassword",
    }

## HTML Routes
To override page:
* create your own html page
* insert _Vars_ into your template. Under _Var_ message or error text will be displayed
* rename html and put under _Template path_
* template will be available under _Path_

List of available routes: 

#### Login
Path: `/login` \
Template path: `template/login_form.html` \
Vars: `{{.error}}`

#### Logout
Path: `/logout` \
Template path: -

#### Registration form
Path: `/register` \
Template path: `template/registration_form.html` \
Vars: `{{.error}}` 

#### Registration success page
Path: `/register/result` \
Template path: `template/registration_form.html` \
Vars: `{{.message}}`

#### Activate result
Path: `/activate/result` \
Template: `template/activation_result.html` \
Vars: `{{.error}}` `{{.message}}`

#### Forget password form
Description: display form for password remind
Path: `/forget-password` \
Template: `forget_password_form.html` \
Vars: `{{.error}}` 

#### Forget password result page
Description: page to show after successfully remind password submission  
Path: `/forget-password/result` \
Template: `forget_password_result.html` \
Vars: `{{.error}}` `{{.message}}`

#### Change password form
Description: display change password form  
Path: `/change-password` \
Template: `change_password_form.html` \
Vars: `{{.error}}`

#### Change password result page
Description: page to show after successfully change password submission
Path: `/change-password/result` \
Template: `change_password_result.html` \
Vars: `{{.error}}` `{{.message}}`


## Routers

### Gin
We recommend to use [Gin](https://github.com/gin-gonic/gin) as main router
To create new `auth`:
```go
auth, err := authless.NewGorillaAuth(conf)
```

Todo:

- [x] Add tests
- [x] Add gorilla http router
- [x] Add default http router
- [x] Forget password mux
- [ ] Forget password gorilla
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
- [ ] Routes as const