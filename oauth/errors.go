package oauth

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/oauth/token"
)

type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string {
	return e.Message
}

func NewErr(code, message string) error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

type authorizeError struct {
	err     error
	request *pkg.AuthorizationRequest
}

func (r *authorizeError) Error() string {
	return r.err.Error()
}

func (r *authorizeError) Unwrap() error {
	return r.err
}

func wrapAuthorizeError(err error, r *pkg.AuthorizationRequest) error {
	return &authorizeError{
		err:     err,
		request: r,
	}
}

type routeErr struct {
	err error
	to  *url.URL
}

func (e *routeErr) Error() string {
	return e.err.Error()
}

func (e *routeErr) Unwrap() error {
	return e.err
}

func wrapRoute(err error, to *url.URL) error {
	return &routeErr{
		err: err,
		to:  to,
	}
}

func wrap(err error, r *pkg.AuthorizationRequest, to *url.URL) error {
	return wrapRoute(wrapAuthorizeError(err, r), to)
}

func needErrorWrite(c *gin.Context) bool {
	return len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK
}

func ErrorWrappingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if needErrorWrite(c) {
			err := c.Errors.Last()

			var oauthErr *Error
			if !errors.As(err, &oauthErr) {
				_ = c.Error(oauthErrWrap(err))
			}
		}
	}
}

func ErrorHandleMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if needErrorWrite(c) {
			err := c.Errors.Last()
			m := parse(err)

			var routeError *routeErr
			if errors.As(err, &routeError) {
				c.Redirect(http.StatusMovedPermanently, m.QueryParam(routeError.to).String())
			} else {
				c.JSON(httpStatus(m.Code), m)
			}
		}
	}
}

func oauthErrWrap(err error) error {
	switch {
	case errors.Is(err, token.ErrAccessTokenNotFound),
		errors.Is(err, token.ErrRefreshTokenNotFound),
		errors.Is(err, token.ErrInvalidRequest),
		errors.Is(err, client.ErrInvalidRequest),
		errors.Is(err, client.ErrInvalidRedirectURI),
		errors.Is(err, client.ErrNotFound),
		errors.Is(err, code.ErrParameterMissing),
		errors.Is(err, code.ErrNotFound):
		return NewErr(pkg.ErrInvalidRequest, err.Error())
	case errors.Is(err, token.ErrUnauthorized),
		errors.Is(err, token.ErrTokenCannotGrant),
		errors.Is(err, client.ErrAuthentication):
		return NewErr(pkg.ErrInvalidGrant, err.Error())
	case errors.Is(err, client.ErrInvalidScope):
		return NewErr(pkg.ErrInvalidScope, err.Error())
	default:
		fmt.Printf("%v", err)
		return NewErr(pkg.ErrServerError, "internal server error")
	}
}

func parse(err error) pkg.ErrResponse {
	var er pkg.ErrResponse

	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		er = pkg.NewErrResponse(oauthErr.Code, oauthErr.Message)
	} else {
		fmt.Printf("%v", err)
		er = pkg.NewErrResponse(pkg.ErrServerError, "unknown error")
	}

	var requestErr *authorizeError
	if errors.As(err, &requestErr) {
		er.State = requestErr.request.State
	}
	return er
}

func httpStatus(c string) int {
	switch c {
	case pkg.ErrInvalidRequest, pkg.ErrInvalidGrant, pkg.ErrInvalidScope, pkg.ErrInvalidClient:
		return http.StatusBadRequest
	case pkg.ErrAccessDenied, pkg.ErrUnauthorizedClient:
		return http.StatusUnauthorized
	case pkg.ErrTemporaryUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
