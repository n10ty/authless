package authless

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type GinAuth struct {
	auth *Auth
}

func NewGinAuth(config *Config) (*GinAuth, error) {
	err := initAuth(config)
	if err != nil {
		return nil, err
	}

	return &GinAuth{auth: a}, nil
}

func (g *GinAuth) AuthRequired(handler func(c *gin.Context)) func(c *gin.Context) {
	return func(context *gin.Context) {
		doAuth(g.auth.config.Type == AuthTypeRedirect, context.Writer, context.Request)
		if context.Writer.Status() == http.StatusUnauthorized {
			return
		}
		handler(context)
	}
}

func (g *GinAuth) InitServiceRoutes(router *gin.Engine) {
	router.LoadHTMLGlob("template/*")
	auth := router.Group("/auth")
	auth.Any("/login", gin.WrapF(g.auth.authHandler.LoginHandler))
	auth.GET("/logout", gin.WrapF(g.auth.authHandler.LogoutHandler))
	auth.POST("/register", gin.WrapF(g.auth.authHandler.RegistrationHandler))
	auth.GET("/activate", gin.WrapF(g.auth.authHandler.ActivationHandler))
	auth.POST("/remind-password/request", gin.WrapF(g.auth.authHandler.RemindPasswordHandler))

	router.GET("/success", func(c *gin.Context) {
		c.HTML(http.StatusOK, "registration_success.html", nil)
	})

	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login_form.html", gin.H{"error": c.Query("error")})
	})
	router.GET("/logout", gin.WrapF(g.auth.authHandler.LogoutHandler))
	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "registration_form.html", gin.H{"error": c.Query("error")})
	})
	router.GET("/activate-result", func(c *gin.Context) {
		err := c.Query("error")
		if err != "" {
			c.HTML(http.StatusOK, "activation_error.html", gin.H{"error": c.Query("error")})
			return
		}
		c.HTML(http.StatusOK, "activation_success.html", nil)
		return
	})
}

func (g *GinAuth) SetActivationTokenSender(senderFunc TokenSenderFunc) {
	g.auth.SetActivationTokenSenderFunc(senderFunc)
}

func (g *GinAuth) SetPasswordReminder(remindPasswordFunc RemindPasswordFunc) {
	g.auth.SetRemindPasswordFunc(remindPasswordFunc)
}
