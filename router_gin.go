package authless

import (
	"net/http"

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
	return func(context *gin.Context) {
		m.Auth(&NoBody{}).ServeHTTP(context.Writer, context.Request)
		if context.Writer.Status() == http.StatusUnauthorized {
			return
		}
		handler(context)
	}
}

func (g *GinAuth) AuthRequiredWithRedirect(handler func(c *gin.Context)) func(c *gin.Context) {
	m := g.auth.auth.Middleware()
	return func(context *gin.Context) {
		m.Trace(newRedirectHandler("/login")).ServeHTTP(context.Writer, context.Request)
		handler(context)
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

	if g.auth.config.Type == AuthTypeRedirect {
		router.GET("/register", func(c *gin.Context) {
			c.HTML(http.StatusOK, "register.html", gin.H{"error": c.Query("error")})
		})
		router.GET("/login", func(c *gin.Context) {
			c.HTML(http.StatusOK, "login.html", gin.H{"error": c.Query("error")})
		})
	}
}

func (g *GinAuth) SetTokenSender(senderFunc TokenSenderFunc) {
	g.auth.SetTokenSender(senderFunc)
}

func (g *GinAuth) register(c *gin.Context) {
	g.auth.register(c.Writer, c.Request)
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
