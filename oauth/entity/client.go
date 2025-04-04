package entity

import (
	"oauth-server-go/sql"
	"time"
)

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Secret       string
	OwnerID      string
	Redirects    sql.Strings `gorm:"column:redirect_uris"`
	Scopes       sql.Strings
	RegisteredAt time.Time `gorm:"column:reg_dt"`
}

func (c Client) TableName() string {
	return "users.oauth2_client"
}
