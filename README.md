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

	router.Handle("GET", "/private", auth.AuthRequired(private))

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	router.GET("/public", func(c *gin.Context) {
		c.String(200, "public")
	})
	log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Config

```yaml
appName: myapp.com
secret: mysecret
disablexsrf: false
type: redirect // 'redirect' or 'api'
storage:
  type: mysql
  host: localhost
  port: 3306
  username: root
  password: 12345
  dbname: test_auth
```

