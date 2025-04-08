package handler

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
)

type RedirectErr struct {
	Err      error
	Redirect *url.URL
}

func NewRedirectErr(err error, u *url.URL) error {
	return &RedirectErr{
		Err:      err,
		Redirect: u,
	}
}

func NewRedirectErrMsg(err error, m string, u *url.URL) error {
	return &RedirectErr{
		Err:      oauth.NewErr(err, m),
		Redirect: u,
	}
}

func (e *RedirectErr) Unwrap() error {
	return e.Err
}

func (e *RedirectErr) Error() string {
	return e.Err.Error()
}

func errHandler(c *gin.Context, err error) {
	m := parse(err)
	var e *RedirectErr
	if ok := errors.As(err, &e); ok {
		q := e.Redirect.Query()
		q.Set("error", m.Code)
		q.Set("error_description", m.Message)
		e.Redirect.RawQuery = q.Encode()
		c.Redirect(http.StatusMovedPermanently, e.Redirect.String())
	} else {
		c.JSON(status(err), m)
	}
}

func parse(err error) oauth.ErrResponse {
	var e *oauth.Err
	if errors.As(err, &e) {
		return oauth.NewErrResponse(e.Error(), e.Message)
	}
	fmt.Printf("%v", err)
	return oauth.NewErrResponse(oauth.ErrServerError.Error(), "internal server error")
}

func status(err error) int {
	if errors.Is(err, oauth.ErrInvalidRequest) {
		return http.StatusBadRequest
	} else if errors.Is(err, oauth.ErrAccessDenied) {
		return http.StatusUnauthorized
	}
	return http.StatusInternalServerError
}
