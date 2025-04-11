package handler

import (
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"strconv"
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

func implicitFlow(r *oauth.AuthorizationRequest, src any, redirect *url.URL) error {
	if r.ResponseType != oauth.ResponseTypeToken {
		return nil
	}
	if token, ok := src.(*entity.Token); ok {
		q := redirect.Query()
		q.Set("access_token", token.InspectValue())
		q.Set("token_type", string(oauth.TokenTypeBearer))
		q.Set("expires_in", strconv.FormatUint(uint64(token.InspectExpiredAt()), 10))
		q.Set("scope", token.InspectScope())
		q.Set("state", r.State)
		redirect.Fragment = q.Encode()
	}
	return nil
}
