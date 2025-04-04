package entity

import (
	"database/sql/driver"
	"oauth-server-go/sql"
	"time"
)

// CodeChallenge OAuth2 인증 코드 사용(교환) 때 인증에 사용될 코드(RFC 7636)
type CodeChallenge string

func (c *CodeChallenge) Scan(src any) error {
	b := src.([]byte)
	*c = CodeChallenge(b)
	return nil
}

func (c CodeChallenge) Valuer() (driver.Value, error) {
	return string(c), nil
}

// CodeChallengeMethod [CodeChallenge] 인코딩 방법
type CodeChallengeMethod string

const (
	CodeChallengePlan CodeChallengeMethod = "plain"
	CodeChallengeS256 CodeChallengeMethod = "S256"
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
	CodeChallenge       CodeChallenge
	CodeChallengeMethod CodeChallengeMethod
	IssuedAt, ExpiredAt time.Time
}

func (c AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}
