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
	router.Any("/auth/login", gin.WrapF(g.auth.authHandler.LoginHandler))
	router.GET("/auth/logout", gin.WrapF(g.auth.authHandler.LogoutHandler))
	router.POST("/auth/register", gin.WrapF(g.auth.authHandler.RegistrationHandler))
	router.GET("/auth/activate", gin.WrapF(g.auth.authHandler.ActivationHandler))

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

func (g *GinAuth) SetTokenSender(senderFunc TokenSenderFunc) {
	g.auth.SetActivationTokenSender(senderFunc)
}
