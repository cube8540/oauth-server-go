package entity

import (
	"oauth-server-go/oauth"
	"oauth-server-go/sql"
	"slices"
	"time"
)

// Scope OAuth2 스코프
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

// GrantedScopes Scope 를 배열로 묶은 타입
type GrantedScopes []Scope

// GetAll v를 코드로 가지는 Scope 를 모두 찾아 반환한다. 만약 찾을 수 없는 스코프가 있을 경우 에러를 반환한다.
func (s GrantedScopes) GetAll(v []string) ([]Scope, error) {
	if len(v) == 0 {
		return s, nil
	}
	if len(v) > len(s) {
		return nil, oauth.NewErr(oauth.ErrInvalidScope, "scope cannot grant")
	}
	var scopes []Scope
	for _, rs := range v {
		idx := slices.IndexFunc(s, func(cs Scope) bool {
			return cs.Code == rs
		})
		if idx < 0 {
			return nil, oauth.NewErr(oauth.ErrInvalidScope, "scope cannot grant")
		}
		scopes = append(scopes, s[idx])
	}
	return scopes, nil
}

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Name         string           `gorm:"column:client_name"`
	Type         oauth.ClientType `gorm:"column:client_type"`
	Secret       string
	OwnerID      string
	Redirects    sql.Strings   `gorm:"column:redirect_uris"`
	Scopes       GrantedScopes `gorm:"many2many:users.oauth2_client_scope;joinForeignKey:client_id;joinReferences:scope_id"`
	RegisteredAt time.Time     `gorm:"column:reg_dt"`
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

func (c *Client) ContainsRedirect(url string) bool {
	return slices.Contains(c.Redirects, url)
}

func (c *Client) TableName() string {
	return "users.oauth2_client"
}
