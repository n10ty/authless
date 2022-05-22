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
	auth.POST("/change-password/request", gin.WrapF(g.auth.authHandler.ChangePasswordRequestHandler))
	auth.POST("/change-password", gin.WrapF(g.auth.authHandler.ChangePasswordHandler))

	if g.auth.config.Type == AuthTypeRedirect {
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
		router.GET("/activate/result", func(c *gin.Context) {
			err := c.Query("error")
			params := gin.H{}
			if err != "" {
				params["error"] = c.Query("error")
			} else {
				params["success"] = "Activated successfully"
			}
			c.HTML(http.StatusOK, "activation_result.html", params)
			return
		})
		router.GET("/forget-password", func(c *gin.Context) {
			c.HTML(http.StatusOK, "forget_password_form.html", gin.H{"error": c.Query("error")})
		})
		router.GET("/forget-password-success", func(c *gin.Context) {
			c.HTML(http.StatusOK, "forget_password_success.html", nil)
		})
		router.GET("/change-password", func(c *gin.Context) {
			c.HTML(http.StatusOK, "change_password_form.html", gin.H{"token": c.Query("token")})
		})
		router.GET("/change-password/result", func(c *gin.Context) {
			err := c.Query("error")
			params := gin.H{}
			if err != "" {
				params["error"] = c.Query("error")
			} else {
				params["success"] = "Password has been changed successfully"
			}
			c.HTML(http.StatusOK, "change_password_result.html", params)
			return
		})
	}
}

func (g *GinAuth) SetActivationTokenSenderFunc(senderFunc TokenSenderFunc) {
	g.auth.SetActivationTokenSenderFunc(senderFunc)
}

func (g *GinAuth) SetChangePasswordRequestFunc(f ChangePasswordRequestFunc) {
	g.auth.SetChangePasswordRequestFunc(f)
}
