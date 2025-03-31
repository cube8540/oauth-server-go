package oauth

import "oauth-server-go/sql"

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Secret       string
	OwnerID      string
	RedirectUris sql.Strings
	Scopes       sql.Strings
}

func (c Client) TableName() string {
	return "users.oauth2_client"
}
