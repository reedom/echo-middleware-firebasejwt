echo-middleware-firebasejwt
===========================

An [Echo][] middleware to authenticate a user through [Firebase's JWT functionality][],
based on [Echo's original JWT auth middleware][].

[Echo]: https://echo.labstack.com/
[Echo's original JWT auth middleware]: https://github.com/labstack/echo/blob/master/middleware/jwt.go
[Firebase's JWT functionality]: https://firebase.google.com/docs/auth/admin/verify-id-tokens

### Install

```sh
go get -u github.com/reedom/echo-middleware-firebasejwt
```

### Usage

Import packages.

```go
import (
    firebase "firebase.google.com/go"
    "github.com/reedom/echo-middleware-firebasejwt"
)
```

Initialize a Firebase App.

```go
ctx := context.Background()
app, err := firebase.NewApp(ctx, nil)
if err != nil {
    panic(err)
}
```

Set up the middleware with the default config.

```go
e.Use(firebasejwt.Default(app))
```

Or with a custom config.

```go
jwtConfig := firebasejwt.JWTConfig{
    App:              app,
    Skipper:          authSkipper,
    ContextSpecifier: contextSpecifier,
}
e.Use(firebasejwt.With(jwtConfig))

////

func authSkipper(e echo.Context) bool {
	path := e.Request().URL.Path
	if path == "/" || path == "/login" {
		return true
	}
	return false
}

type AuthUser struct {
	Token *auth.Token
	Email string
	Name  string
}

func contextSpecifier(token *auth.Token) (string, interface{}) {
	user := AuthUser{
		Token: token,
		Email: token.Claims["email"].(string),
		Name:  token.Claims["name"].(string),
	}
	return "authUser", user
}
```

### License

MIT

