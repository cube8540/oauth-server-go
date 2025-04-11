package handler

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
)

type requestFailed struct {
	err     error
	request *oauth.AuthorizationRequest
}

func (r *requestFailed) Error() string {
	return r.err.Error()
}

func (r *requestFailed) Unwrap() error {
	return r.err
}

func wrap(err error, r *oauth.AuthorizationRequest) error {
	return &requestFailed{
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

func route(err error, to *url.URL) error {
	return &routeErr{
		err: err,
		to:  to,
	}
}

func routeWrap(err error, r *oauth.AuthorizationRequest, to *url.URL) error {
	return route(wrap(err, r), to)
}

func parse(err error) oauth.ErrResponse {
	var er oauth.ErrResponse

	var oauthErr *oauth.Error
	if errors.As(err, &oauthErr) {
		er = oauth.NewErrResponse(oauthErr.Code, oauthErr.Message)
	} else {
		fmt.Printf("%v", err)
		er = oauth.NewErrResponse(oauth.ErrServerError, "unknown error")
	}

	var requestErr *requestFailed
	if errors.As(err, &requestErr) {
		er.State = requestErr.request.State
	}
	return er
}

func ErrorHandleMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK {
			err := c.Errors.Last()
			m := parse(err)

			var routeError *routeErr
			if errors.As(err, &routeError) {
				c.Redirect(http.StatusMovedPermanently, m.QueryParam(routeError.to).String())
			} else {
				c.JSON(oauth.HttpStatus(m.Code), m)
			}
		}
	}
}
