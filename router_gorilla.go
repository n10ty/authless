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
		doAuth(g.auth.config.Type == AuthTypeTemplate, ww, r)
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
	router.Path("/auth/forget-password").Methods(http.MethodPost).HandlerFunc(g.auth.authHandler.ForgetPasswordRequestHandler)
	router.Path("/auth/change-password").Methods(http.MethodPost).HandlerFunc(g.auth.authHandler.ChangePasswordHandler)

	if g.auth.config.Type == AuthTypeTemplate {
		router.Path("/login").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				writeTemplate(w, "template/login_form.html", map[string]any{"error": template.HTML(r.FormValue("error"))})
			})

		router.Path("/logout").Methods(http.MethodGet).HandlerFunc(g.auth.authHandler.LogoutHandler)
		router.Path("/register").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				writeTemplate(w, "template/registration_form.html", map[string]any{"error": template.HTML(r.FormValue("error"))})
			})
		router.Path("/register/success").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeTemplate(w, "template/registration_result.html", map[string]any{"message": template.HTML(r.FormValue("Successfully registered"))})
		})
		router.Path("/activate/result").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				params := make(map[string]any)
				err := r.FormValue("error")
				if err != "" {
					params["error"] = err
				} else {
					params["message"] = "Activated successfully"
				}
				writeTemplate(w, "template/activation_result.html", params)
			})
		router.Path("/forget-password").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				writeTemplate(w, "template/forget_password_form.html", map[string]any{})
			})
		router.Path("/forget-password/result").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				params := make(map[string]any)
				err := r.FormValue("error")
				if err != "" {
					params["error"] = err
				} else {
					params["message"] = "Change password request has been sent. Please check your email."
				}
				writeTemplate(w, "template/forget_password_result.html", params)
			})
		router.Path("/change-password").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				writeTemplate(w, "template/change_password_form.html", map[string]any{"error": template.HTML(r.FormValue("error")), "token": template.HTML(r.FormValue("token"))})
			})

		router.Path("/change-password/result").Methods(http.MethodGet).HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				writeTemplate(w, "template/change_password_result.html", map[string]any{"error": template.HTML(r.FormValue("error"))})
			})
	}
}

func (g *GorillaAuth) SetActivationTokenSenderFunc(f ActivateAccountFunc) {
	g.auth.SetActivationTokenSenderFunc(f)
}

func (g *GorillaAuth) SetChangePasswordRequestFunc(f ChangePasswordRequestFunc) {
	g.auth.SetChangePasswordRequestFunc(f)
}

func writeTemplate(w http.ResponseWriter, path string, params map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tplTxt, err := template.ParseGlob(path)
	if err != nil {
		log.Errorf("Error during load html template registration_form.html: %s", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	tplTxt.Execute(w, params)
}
