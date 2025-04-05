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
	Err      *oauth.Err
	Redirect string
}

func NewRedirectErr(err *oauth.Err, uri string) error {
	return &RedirectErr{
		Err:      err,
		Redirect: uri,
	}
}

func (e *RedirectErr) Unwrap() error {
	return e.Err
}

func (e *RedirectErr) Error() string {
	return e.Err.Error()
}

func (e RedirectErr) Message() string {
	return e.Err.Message
}

func errHandler(err error, c *gin.Context) {
	m := parse(err)
	var e *RedirectErr
	if ok := errors.As(err, &e); ok {
		to, _ := url.Parse(e.Redirect)
		q := to.Query()
		q.Set("error", m.Code)
		q.Set("error_description", m.Message)
		c.Redirect(http.StatusMovedPermanently, to.String())
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
	}
	return http.StatusInternalServerError
}
