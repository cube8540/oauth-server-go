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
	Name         string `gorm:"column:client_name"`
	Secret       string
	OwnerID      string
	Redirects    sql.Strings `gorm:"column:redirect_uris"`
	Scopes       sql.Strings
	RegisteredAt time.Time `gorm:"column:reg_dt"`
}

func (c Client) RedirectURL(url string) (string, error) {
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

func (c Client) HasAllScopes(s []string) bool {
	for _, e := range s {
		if !slices.Contains(c.Scopes, e) {
			return false
		}
	}
	return true
}

func (c Client) ContainsRedirect(url string) bool {
	return slices.Contains(c.Redirects, url)
}

func (c Client) TableName() string {
	return "users.oauth2_client"
}
