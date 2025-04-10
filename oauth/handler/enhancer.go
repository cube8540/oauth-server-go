package handler

import (
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

type Enhancer func(r *oauth.AuthorizationRequest, src any, redirect *url.URL) error

func chaining(e ...Enhancer) Enhancer {
	return func(r *oauth.AuthorizationRequest, src any, redirect *url.URL) error {
		u := redirect
		for _, h := range e {
			err := h(r, src, u)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func authorizationCodeFlow(r *oauth.AuthorizationRequest, src any, redirect *url.URL) error {
	if r.ResponseType != oauth.ResponseTypeCode {
		return nil
	}
	if code, ok := src.(*entity.AuthorizationCode); ok {
		q := redirect.Query()
		q.Set("code", code.Value)
		if code.State != "" {
			q.Set("state", code.State)
		}
		redirect.RawQuery = q.Encode()
	}
	return nil
}
