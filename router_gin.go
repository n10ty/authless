package authless

import (
	"net/http"

	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-pkgz/auth/token"
)

type GinAuth struct {
	auth *Auth
}

func NewGinAuth(configPath string) (*GinAuth, error) {
	err := initAuth(configPath)
	if err != nil {
		return nil, err
	}

	return &GinAuth{auth: a}, nil
}

func (g *GinAuth) AuthRequired(handler func(c *gin.Context)) func(c *gin.Context) {
	m := g.auth.auth.Middleware()
	if g.auth.config.Type == AuthTypeRedirect {
		return func(context *gin.Context) {
			m.Trace(newRedirectHandler("/login")).ServeHTTP(context.Writer, context.Request)
			handler(context)
		}
	} else {
		return func(context *gin.Context) {
			m.Auth(&NoBody{}).ServeHTTP(context.Writer, context.Request)
			if context.Writer.Status() == http.StatusUnauthorized {
				return
			}
			handler(context)
		}
	}
}

func (g *GinAuth) InitServiceRoutes(router *gin.Engine) {
	authRoutes, _ := g.auth.auth.Handlers()
	router.LoadHTMLGlob("template/*")
	router.Any("/auth/*auth", gin.WrapH(authRoutes))
	router.GET("/success", func(c *gin.Context) {
		c.HTML(http.StatusOK, "success.html", nil)
	})
	router.POST("/register", g.register)

	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{"error": c.Query("error")})
	})
	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": c.Query("error")})
	})
	router.GET("/activate", g.activateWithRedirect)
	router.GET("/activate-result", func(c *gin.Context) {
		err := c.Query("error")
		if err != "" {
			c.HTML(http.StatusOK, "activate-error.html", gin.H{"error": c.Query("error")})
			return
		}
		c.HTML(http.StatusOK, "activate-success.html", nil)
		return
	})
}

func (g *GinAuth) SetTokenSender(senderFunc TokenSenderFunc) {
	g.auth.SetTokenSender(senderFunc)
}

func (g *GinAuth) register(c *gin.Context) {
	email, ok := c.GetPostForm("email")
	if email == "" || !ok {
		c.Redirect(http.StatusMovedPermanently, "/register?error=Bad request")
	}
	password, ok := c.GetPostForm("password")
	if password == "" || !ok {
		c.Redirect(http.StatusMovedPermanently, "/register?error=Bad request")
	}

	err := g.auth.register(email, password)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("/register?error=%s", err))
	}

	c.Redirect(http.StatusFound, "/success")
}

func (g *GinAuth) activateWithRedirect(c *gin.Context) {
	token := c.Query("token")

	err := g.auth.activate(token)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("/activate-result?error=%s", err))
	}
	c.Redirect(http.StatusMovedPermanently, "/activate-result")
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
