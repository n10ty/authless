package authless

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-pkgz/auth/token"
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
	if g.auth.config.Type == AuthTypeRedirect {
		return func(context *gin.Context) {
			g.auth.doAuth(false)(newRedirectHandler("/login")).ServeHTTP(context.Writer, context.Request)
			handler(context)
		}
	} else {
		return func(context *gin.Context) {
			g.auth.doAuth(true)(&NoBody{}).ServeHTTP(context.Writer, context.Request)
			if context.Writer.Status() == http.StatusUnauthorized {
				return
			}
			handler(context)
		}
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
	router.GET("/logout", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/auth/logout")
	})
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

type RedirectHandler struct {
	redirectUrl string
}

func newRedirectHandler(redirectUrl string) *RedirectHandler {
	return &RedirectHandler{redirectUrl: redirectUrl}
}

func (n *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := token.GetUserInfo(r)
	if err != nil {
		http.Redirect(w, r, n.redirectUrl, http.StatusFound)
	}
}

type NoBody struct {
}

func (n *NoBody) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}
