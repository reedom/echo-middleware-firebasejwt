package firebasejwt

import (
	"context"
	"net/http"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type (
	// JWTConfig defines the config for JWT middleware.
	JWTConfig struct {
		// Firebase app.
		// Required.
		App *firebase.App

		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper

		// BeforeFunc defines a function which is executed just before the middleware.
		BeforeFunc middleware.BeforeFunc

		// SuccessHandler defines a function which is executed for a valid token.
		SuccessHandler JWTSuccessHandler

		// ErrorHandler defines a function which is executed for an invalid token.
		// It may be used to define a custom JWT error.
		ErrorHandler JWTErrorHandler

		// JWTContextSpecifier defines a function which returns (context-key, token-value).
		// The token-value will be stored into context with context-key.
		// Optional. Default values are ("user", *auth.Token)
		ContextSpecifier JWTContextSpecifier

		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		TokenLookup string

		// AuthScheme to be used in the Authorization header.
		// Optional. Default value "Bearer".
		AuthScheme string
	}

	// JWTSuccessHandler defines a function which is executed for a valid token.
	JWTSuccessHandler func(echo.Context)

	// JWTErrorHandler defines a function which is executed for an invalid token.
	JWTErrorHandler func(error) error

	// JWTContextSpecifier defines a function which returns (context-key, token-value).
	// The token-value will be stored into context with context-key.
	// Optional. Default values are ("user", *auth.Token)
	JWTContextSpecifier func(*auth.Token) (string, interface{})

	jwtExtractor func(echo.Context) (string, error)
)

// Errors
var (
	ErrJWTMissing = echo.NewHTTPError(http.StatusBadRequest, "missing or malformed jwt")
)

var (
	// DefaultJWTConfig is the default JWT auth middleware config.
	DefaultFirebaseJWTConfig = JWTConfig{
		Skipper: middleware.DefaultSkipper,
		ContextSpecifier: func(token *auth.Token) (string, interface{}) {
			return "user", token
		},
		TokenLookup: "header:" + echo.HeaderAuthorization,
		AuthScheme:  "Bearer",
	}
)

// JWT returns a JSON Web Token (JWT) auth middleware.
//
// For valid token, it sets the user in context and calls next handler.
// For invalid token, it returns "401 - Unauthorized" error.
// For missing token, it returns "400 - Bad Request" error.
func Default(app *firebase.App) echo.MiddlewareFunc {
	c := DefaultFirebaseJWTConfig
	c.App = app
	return With(c)
}

// JWTWithConfig returns a JWT auth middleware with config.
// See: `JWT()`.
func With(config JWTConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultFirebaseJWTConfig.Skipper
	}
	if config.ContextSpecifier == nil {
		config.ContextSpecifier = DefaultFirebaseJWTConfig.ContextSpecifier
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultFirebaseJWTConfig.TokenLookup
	}
	if config.AuthScheme == "" {
		config.AuthScheme = DefaultFirebaseJWTConfig.AuthScheme
	}

	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := jwtFromHeader(parts[1], config.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = jwtFromQuery(parts[1])
	case "cookie":
		extractor = jwtFromCookie(parts[1])
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}

			auth, err := extractor(c)
			if err != nil {
				if config.ErrorHandler != nil {
					return config.ErrorHandler(err)
				}
				return err
			}

			ctx := context.Background()
			client, err := config.App.Auth(ctx)
			if err != nil {
				if config.ErrorHandler != nil {
					return config.ErrorHandler(err)
				}
				return err
			}

			if token, err := client.VerifyIDToken(ctx, auth); err == nil {
				contextKey, tokenValue := config.ContextSpecifier(token)
				// Store user information from token into context.
				c.Set(contextKey, tokenValue)
				if config.SuccessHandler != nil {
					config.SuccessHandler(c)
				}
				return next(c)
			}

			if config.ErrorHandler != nil {
				return config.ErrorHandler(err)
			}
			return &echo.HTTPError{
				Code:     http.StatusUnauthorized,
				Message:  "invalid or expired jwt",
				Internal: err,
			}
		}
	}
}

// jwtFromHeader returns a `jwtExtractor` that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrJWTMissing
	}
}

// jwtFromQuery returns a `jwtExtractor` that extracts token from the query string.
func jwtFromQuery(param string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", ErrJWTMissing
		}
		return token, nil
	}
}

// jwtFromCookie returns a `jwtExtractor` that extracts token from the named cookie.
func jwtFromCookie(name string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrJWTMissing
		}
		return cookie.Value, nil
	}
}
