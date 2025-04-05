package entity

import (
	"oauth-server-go/oauth"
	"oauth-server-go/sql"
	"time"
)

type AuthorizationCode struct {
	ID                  uint
	Value               string `gorm:"column:code"`
	ClientID            uint
	Client              Client
	Username            string
	State               string
	Redirect            string
	Scopes              sql.Strings
	CodeChallenge       oauth.CodeChallenge
	CodeChallengeMethod oauth.CodeChallengeMethod
	IssuedAt, ExpiredAt time.Time
}

func (c AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}
