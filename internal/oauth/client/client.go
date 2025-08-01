package client

import (
	"fmt"
	oautherr "oauth-server-go/internal/oauth/errors"
	"slices"
	"time"
)

// Type OAuth 클라이언트 타입 [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
type Type string

const (
	TypePublic       Type = "public"
	TypeConfidential Type = "confidential"
)

// Client OAuth2 클라이언트
type Client struct {
	id           string
	name         string
	t            Type
	secret       string
	owner        string
	redirects    []string
	scopes       []string
	registeredAt time.Time
}

func New(id, secret, name string, t Type) *Client {
	return &Client{
		id:           id,
		name:         name,
		t:            t,
		secret:       secret,
		registeredAt: time.Now(),
	}
}

func (c *Client) AddRedirect(uri string) {
	c.redirects = append(c.redirects, uri)
}

func (c *Client) AddScope(s string) {
	c.scopes = append(c.scopes, s)
}

func (c *Client) Id() string {
	return c.id
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) T() Type {
	return c.t
}

func (c *Client) Secret() string {
	return c.secret
}

func (c *Client) Owner() string {
	return c.owner
}

func (c *Client) Redirects() []string {
	return c.redirects
}

func (c *Client) Scopes() []string {
	return c.scopes
}

func (c *Client) RegisteredAt() time.Time {
	return c.registeredAt
}

func (c *Client) SetRegisteredAt(t time.Time) {
	c.registeredAt = t
}

// ValidateRedirectURI 클라이언트에 등록된 라다이렉트 URI를 검증하고 반환한다.
// 리다이렉트 URI 검증에 실패하면 에러를 반환한다.
//
// 다음과 같은 규칙을 가지고 동작한다.
//
//	1.등록된 리다이렉트 URI가 하나인 경우 입력 받은 값과 같거나, 입력 받은 값이 비어 있을 경우에 URI를 반환한다.
//	2.등록된 리다이렉트 URI가 2개 이상인 경우 입력 받은 URI와 같은 URI을 찾아 반환한다. 만약 입력 받은 URI가 비어있을 경우 에러를 반환한다.
func (c *Client) ValidateRedirectURI(uri string) (string, error) {
	if len(c.redirects) == 1 {
		u := c.redirects[0]
		if uri != "" && u != uri {
			return "", fmt.Errorf("%w: redirect url(%s) is not found", oautherr.ErrInvalidRequest, uri)
		}
		return u, nil
	}

	if uri == "" {
		return "", fmt.Errorf("%w: empty string (or nil)", oautherr.ErrMissingParameter)
	}

	i := slices.Index(c.redirects, uri)
	if i < 0 {
		return "", fmt.Errorf("%w: redirect url(%s) is not found", oautherr.ErrInvalidRequest, uri)
	}
	return c.redirects[i], nil
}
