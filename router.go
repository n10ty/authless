package authless

const (
	routePathWildcard         = "template/*"
	routeAuthGroup            = "/auth"
	routeLogin                = "/login"
	routeLogout               = "/logout"
	routeRegister             = "/register"
	routeActivate             = "/activate"
	routeForgetPassword       = "/forget-password"
	routeChangePassword       = "/change-password"
	routeRegisterSuccess      = "/register/success"
	routeActivateResult       = "/activate/result"
	routeForgetPasswordResult = "/forget-password/result"
	routeChangePasswordResult = "/change-password/result"

	routeAuthLogin          = routeAuthGroup + routeLogin
	routeAuthLogout         = routeAuthLogin + routeLogout
	routeAuthRegister       = routeAuthLogin + routeRegister
	routeAuthActivate       = routeAuthLogin + routeActivate
	routeAuthForgetPassword = routeAuthLogin + routeForgetPassword
	routeAuthChangePassword = routeAuthLogin + routeChangePassword
)
