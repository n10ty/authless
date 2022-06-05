//go:build pack_templates
// +build pack_templates

package template

var activationResult=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Activate account</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Activate account</div><div class="card-body"><p>{{.error}}</p><p>{{.message}}</p></div></div></div></div></div></main></body></html>`

var changePasswordForm=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Change password</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Login</div><div class="card-body"><p style="color:red;">{{.error}}</p><form action="/auth/change-password" method="POST"><div class="form-group row"><label for="password" class="col-md-4 col-form-label text-md-right">Password</label><div class="col-md-6"><input type="password" id="password" class="form-control" name="password" required></div></div><input type="hidden" id="token" hidden="hidden" class="form-control" value="{{.token}}" name="token" required><div class="col-md-6 offset-md-4"><button type="submit" class="btn btn-primary">Submit</button></div></form></div></div></div></div></div></main></body></html>`

var changePasswordResult=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Change password</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Change password</div><div class="card-body"><p>{{.error}}</p><p>{{.message}}</p></div></div></div></div></div></main></body></html>`

var forgetPasswordForm=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Forget password</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Remind password</div><div class="card-body"><p style="color:red;">{{.error}}</p><form action="/auth/change-password/request" method="POST"><div class="form-group row"><label for="email_address" class="col-md-4 col-form-label text-md-right">E-Mail</label><div class="col-md-6"><input type="text" id="email_address" class="form-control" name="email" required autofocus></div></div><div class="col-md-6 offset-md-4"><button type="submit" class="btn btn-primary">Login</button></div></form></div></div></div></div></div></main></body></html>`

var forgetPasswordResult=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Remind password request</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Remind password</div><div class="card-body"><p>{{.error}}</p><p>{{.message}}</p></div></div></div></div></div></main></body></html>`

var loginForm=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Login</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Login</div><div class="card-body"><p style="color:red;">{{.error}}</p><form action="/auth/login" method="POST"><div class="form-group row"><label for="email_address" class="col-md-4 col-form-label text-md-right">E-Mail</label><div class="col-md-6"><input type="text" id="email_address" class="form-control" name="email" required autofocus></div></div><div class="form-group row"><label for="password" class="col-md-4 col-form-label text-md-right">Password</label><div class="col-md-6"><input type="password" id="password" class="form-control" name="password" required></div></div><div class="col-md-6 offset-md-4"><button type="submit" class="btn btn-primary">Login</button><a href="/forget-password" class="btn btn-link">Forgot Your Password?</a></div></form></div></div></div></div></div></main></body></html>`

var registrationForm=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Registration</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-6"><div class="card"><div class="card-header">Register</div><div class="card-body"><p style="color:red;">{{.error}}</p><form action="/auth/register" method="POST"><div class="form-group row"><label for="email_address" class="col-md-4 col-form-label text-md-right">E-Mail</label><div class="col-md-6"><input type="text" id="email_address" class="form-control" name="email" required autofocus></div></div><div class="form-group row"><label for="password" class="col-md-4 col-form-label text-md-right">Password</label><div class="col-md-6"><input type="password" id="password" class="form-control" name="password" required></div></div><div class="col-md-6 offset-md-4"><button type="submit" class="btn btn-primary">Register</button></div></form></div></div></div></div></div></main></body></html>`

var registrationResult=`<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css"><script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><!doctype html><html lang="en"><head><!-- Required meta tags --><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><!-- Fonts --><link rel="dns-prefetch" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css"><link rel="stylesheet" href="css/style.css"><link rel="icon" href="Favicon.png"><!-- Bootstrap CSS --><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"><title>Registered successfully</title></head><body><main class="login-form"><div class="container"><div class="row justify-content-center align-items-center" style="height:90vh"><div class="col-md-5"><div class="card"><div class="card-header">Register</div><div class="card-body">{{.message}}</div></div></div></div></div></main></body></html>`
