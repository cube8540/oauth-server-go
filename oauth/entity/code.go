package entity

import (
	"github.com/google/uuid"
	"oauth-server-go/oauth"
	"time"
)

const codeExpiresMinute = time.Minute * 5

type AuthCodeGenerator func() string

func UUIDAuthCodeGenerator() string {
	return uuid.New().String()
}

type AuthorizationCode struct {
	ID                  uint
	Value               string `gorm:"column:code"`
	ClientID            uint
	Client              Client
	Username            string
	State               string
	Redirect            string
	Scopes              []Scope `gorm:"many2many:users.oauth2_code_scopes"`
	CodeChallenge       oauth.CodeChallenge
	CodeChallengeMethod oauth.CodeChallengeMethod
	IssuedAt, ExpiredAt time.Time
}

func NewAuthCode(g AuthCodeGenerator) *AuthorizationCode {
	now := time.Now()
	code := &AuthorizationCode{
		Value:     g(),
		IssuedAt:  now,
		ExpiredAt: now.Add(codeExpiresMinute),
	}
	return code
}

func (c *AuthorizationCode) Set(r *oauth.AuthorizationRequest) error {
	if r.Username == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "username is required")
	}
	c.Username = r.Username
	c.State = r.State
	c.Redirect = r.Redirect
	c.CodeChallenge = r.CodeChallenge
	c.CodeChallengeMethod = r.CodeChallengeMethod
	if c.CodeChallenge != "" && c.CodeChallengeMethod == "" {
		c.CodeChallengeMethod = oauth.CodeChallengePlan
	} else if c.CodeChallenge == "" && c.CodeChallengeMethod != "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "code challenge is required")
	}
	return nil
}

func (c AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}
