package handler

import (
	"log"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

type Enhancer func(src any, redirect *url.URL) error

func chaining(e ...Enhancer) Enhancer {
	return func(src any, redirect *url.URL) error {
		u := redirect
		for _, h := range e {
			err := h(src, u)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func authorizationCodeFlow(src any, redirect *url.URL) error {
	code, ok := src.(*entity.AuthorizationCode)
	if !ok {
		log.Printf("src cannot casting AuthorizationCode")
		return oauth.ErrServerError
	}

	q := redirect.Query()
	q.Set("code", code.Value)
	if code.State != "" {
		q.Set("state", code.State)
	}

	redirect.RawQuery = q.Encode()
	return nil
}
