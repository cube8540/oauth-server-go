package oauth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/pkg/oauth"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
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
	request *oauth.AuthorizationRequest
}

func (r *authorizeError) Error() string {
	return r.err.Error()
}

func (r *authorizeError) Unwrap() error {
	return r.err
}

func wrapAuthorizeError(err error, r *oauth.AuthorizationRequest) error {
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

func wrap(err error, r *oauth.AuthorizationRequest, to *url.URL) error {
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
		return NewErr(oauth.ErrInvalidRequest, err.Error())
	case errors.Is(err, token.ErrUnauthorized),
		errors.Is(err, token.ErrTokenCannotGrant),
		errors.Is(err, client.ErrAuthentication):
		return NewErr(oauth.ErrInvalidGrant, err.Error())
	case errors.Is(err, client.ErrInvalidScope):
		return NewErr(oauth.ErrInvalidScope, err.Error())
	default:
		log.Sugared().Errorf("codes occurred in oauth handler %v", err)
		return NewErr(oauth.ErrServerError, "internal server codes")
	}
}

func parse(err error) oauth.ErrResponse {
	var er oauth.ErrResponse

	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		er = oauth.NewErrResponse(oauthErr.Code, oauthErr.Message)
	} else {
		log.Sugared().Errorf("codes occurred in oauth handler %v", err)
		er = oauth.NewErrResponse(oauth.ErrServerError, "unknown codes")
	}

	var requestErr *authorizeError
	if errors.As(err, &requestErr) {
		er.State = requestErr.request.State
	}
	return er
}

func httpStatus(c string) int {
	switch c {
	case oauth.ErrInvalidRequest, oauth.ErrInvalidGrant, oauth.ErrInvalidScope, oauth.ErrInvalidClient:
		return http.StatusBadRequest
	case oauth.ErrAccessDenied, oauth.ErrUnauthorizedClient:
		return http.StatusUnauthorized
	case oauth.ErrTemporaryUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
