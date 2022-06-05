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
		doAuth(g.auth.config.Type == AuthTypeTemplate, context.Writer, context.Request)
		if context.Writer.Status() == http.StatusUnauthorized {
			return
		}
		handler(context)
	}
}

func (g *GinAuth) InitServiceRoutes(router *gin.Engine) {
	router.LoadHTMLGlob(routePathWildcard)
	auth := router.Group(routeAuthGroup)
	auth.Any(routeLogin, gin.WrapF(g.auth.authHandler.LoginHandler))
	auth.GET(routeLogout, gin.WrapF(g.auth.authHandler.LogoutHandler))
	auth.POST(routeRegister, gin.WrapF(g.auth.authHandler.RegistrationHandler))
	auth.GET(routeActivate, gin.WrapF(g.auth.authHandler.ActivationHandler))
	auth.POST(routeForgetPassword, gin.WrapF(g.auth.authHandler.ForgetPasswordRequestHandler))
	auth.POST(routeChangePassword, gin.WrapF(g.auth.authHandler.ChangePasswordHandler))

	if g.auth.config.Type == AuthTypeTemplate {
		router.GET(routeLogin, func(c *gin.Context) {
			c.HTML(http.StatusOK, "login_form.html", gin.H{"error": c.Query("error")})
		})
		router.GET(routeLogout, gin.WrapF(g.auth.authHandler.LogoutHandler))
		router.GET(routeRegister, func(c *gin.Context) {
			c.HTML(http.StatusOK, "registration_form.html", gin.H{"error": c.Query("error")})
		})
		router.GET(routeRegisterSuccess, func(c *gin.Context) {
			c.HTML(http.StatusOK, "registration_result.html", gin.H{"message": "Successfully registered"})
		})
		router.GET(routeActivateResult, func(c *gin.Context) {
			err := c.Query("error")
			params := gin.H{}
			if err != "" {
				params["error"] = c.Query("error")
			} else {
				params["message"] = "Activated successfully"
			}
			c.HTML(http.StatusOK, "activation_result.html", params)
			return
		})
		router.GET(routeForgetPassword, func(c *gin.Context) {
			c.HTML(http.StatusOK, "forget_password_form.html", gin.H{"error": c.Query("error")})
		})
		router.GET(routeForgetPasswordResult, func(c *gin.Context) {
			err := c.Query("error")
			params := gin.H{}
			if err != "" {
				params["error"] = c.Query("error")
			} else {
				params["message"] = "Change password request has been sent. Please check your email."
			}
			c.HTML(http.StatusOK, "forget_password_result.html", params)
			return
		})
		router.GET(routeChangePassword, func(c *gin.Context) {
			c.HTML(http.StatusOK, "change_password_form.html", gin.H{"token": c.Query("token"), "error": c.Query("error")})
		})
		router.GET(routeChangePasswordResult, func(c *gin.Context) {
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

func (g *GinAuth) SetActivationTokenSenderFunc(senderFunc ActivateAccountFunc) {
	g.auth.SetActivationTokenSenderFunc(senderFunc)
}

func (g *GinAuth) SetChangePasswordRequestFunc(f ChangePasswordRequestFunc) {
	g.auth.SetChangePasswordRequestFunc(f)
}
