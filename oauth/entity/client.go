package entity

import (
	"oauth-server-go/oauth"
	"oauth-server-go/sql"
	"slices"
	"time"
)

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Name         string           `gorm:"column:client_name"`
	Type         oauth.ClientType `gorm:"column:client_type"`
	Secret       string
	OwnerID      string
	Redirects    sql.Strings `gorm:"column:redirect_uris"`
	Scopes       []Scope     `gorm:"many2many:users.oauth2_client_scope;joinForeignKey:client_id;joinReferences:scope_id"`
	RegisteredAt time.Time   `gorm:"column:reg_dt"`
}

func (c *Client) RedirectURL(url string) (string, error) {
	if len(c.Redirects) == 1 {
		u := c.Redirects[0]
		if url != "" && u != url {
			return "", oauth.NewErr(oauth.ErrInvalidRequest, "invalid redirect url")
		}
		return u, nil
	}
	if url == "" {
		return "", oauth.NewErr(oauth.ErrInvalidRequest, "redirect url is required")
	}
	i := slices.Index(c.Redirects, url)
	if i < 0 {
		return "", oauth.NewErr(oauth.ErrInvalidRequest, "invalid redirect url")
	}
	return c.Redirects[i], nil
}

func (c *Client) HasAllScopes(s []string) bool {
	for _, e := range s {
		ok := slices.ContainsFunc(c.Scopes, func(s Scope) bool {
			return s.Code == e
		})
		if !ok {
			return false
		}
	}
	return true
}

func (c *Client) GetScopes(s []string) ([]Scope, error) {
	if len(s) == 0 {
		return c.Scopes, nil
	}
	if len(s) > len(c.Scopes) {
		return nil, oauth.NewErr(oauth.ErrInvalidScope, "scope cannot grant")
	}
	var scopes []Scope
	for _, e := range s {
		idx := slices.IndexFunc(c.Scopes, func(cs Scope) bool {
			return cs.Code == e
		})
		if idx < 0 {
			return nil, oauth.NewErr(oauth.ErrInvalidScope, "scope cannot grant")
		}
		scopes = append(scopes, c.Scopes[idx])
	}
	return scopes, nil
}

func (c *Client) ContainsRedirect(url string) bool {
	return slices.Contains(c.Redirects, url)
}

func (c *Client) TableName() string {
	return "users.oauth2_client"
}

type Scope struct {
	ID           uint
	Code         string
	Name         string    `gorm:"column:scope_name"`
	Desc         string    `gorm:"column:description"`
	RegisteredAt time.Time `gorm:"column:reg_at"`
}

func (s Scope) TableName() string {
	return "users.oauth2_scope"
}
