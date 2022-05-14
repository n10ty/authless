package authless

import (
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"html/template"
)

type GorillaAuth struct {
	auth *Auth
}

func NewGorillaAuth(config *Config) (*GorillaAuth, error) {
	err := initAuth(config)
	if err != nil {
		return nil, err
	}

	return &GorillaAuth{auth: a}, nil
}

func (g *GorillaAuth) AuthRequired(handler func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ww := &responseWriter{}
		ww.reset(w)
		doAuth(g.auth.config.Type == AuthTypeRedirect, ww, r)
		if ww.Status() == http.StatusUnauthorized {
			return
		}
		handler(ww, r)
	}
}

func (g *GorillaAuth) InitServiceRoutes(router *mux.Router) {
	router.Path("/auth/login").HandlerFunc(g.auth.authHandler.LoginHandler)
	router.Path("/auth/logout").Methods(http.MethodGet).HandlerFunc(g.auth.authHandler.LogoutHandler)
	router.Path("/auth/register").Methods(http.MethodPost).HandlerFunc(g.auth.authHandler.RegistrationHandler)
	router.Path("/auth/activate").Methods(http.MethodGet).HandlerFunc(g.auth.authHandler.ActivationHandler)

	router.Path("/success").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "registration_success.html")
	})

	router.Path("/login").Methods(http.MethodGet).HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tplTxt, err := template.ParseGlob("template/login_form.html")
			if err != nil {
				log.Errorf("Error during load html template login_form.html: %s", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			tplTxt.Execute(w, map[string]any{"error": template.HTML(r.FormValue("error"))})
		})

	router.Path("/logout").Methods(http.MethodGet).HandlerFunc(g.auth.authHandler.LogoutHandler)
	router.Path("/register").Methods(http.MethodGet).HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tplTxt, err := template.ParseGlob("template/registration_form.html")
			if err != nil {
				log.Errorf("Error during load html template registration_form.html: %s", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			tplTxt.Execute(w, map[string]any{"error": template.HTML(r.FormValue("error"))})
		})

	router.Path("/activate-result").Methods(http.MethodGet).HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			errorMessage := r.FormValue("error")
			var templatePath string
			params := map[string]any{}
			if errorMessage != "" {
				templatePath = "template/activation_error.html"
				params["error"] = errorMessage
			} else {
				templatePath = "template/activation_success.html"
			}
			tplTxt, err := template.ParseGlob(templatePath)
			if err != nil {
				log.Errorf("Error during load html template activation_error.html: %s", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			tplTxt.Execute(w, params)
		})
}

func (g *GorillaAuth) SetTokenSender(senderFunc TokenSenderFunc) {
	g.auth.SetActivationTokenSender(senderFunc)
}
