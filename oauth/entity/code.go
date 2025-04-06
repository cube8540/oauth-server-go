package entity

import (
	"github.com/google/uuid"
	"oauth-server-go/oauth"
	"oauth-server-go/sql"
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
	Scopes              sql.Strings
	CodeChallenge       oauth.CodeChallenge
	CodeChallengeMethod oauth.CodeChallengeMethod
	IssuedAt, ExpiredAt time.Time
}

func NewAuthCode(c *Client, g AuthCodeGenerator, r *oauth.AuthorizationRequest) (*AuthorizationCode, error) {
	if c == nil {
		return nil, oauth.ErrInvalidClient
	}
	now := time.Now()
	scopes := r.SplitScope()
	if len(scopes) == 0 {
		scopes = c.Scopes
	}
	if !c.HasAllScopes(scopes) {
		return nil, oauth.ErrInvalidScope
	}
	if r.Username == "" {
		return nil, oauth.ErrInvalidRequest
	}
	code := &AuthorizationCode{
		Value:               g(),
		ClientID:            c.ID,
		Username:            r.Username,
		State:               r.State,
		Redirect:            r.Redirect,
		Scopes:              scopes,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		IssuedAt:            now,
		ExpiredAt:           now.Add(codeExpiresMinute),
	}
	if code.CodeChallenge != "" && code.CodeChallengeMethod == "" {
		code.CodeChallengeMethod = oauth.CodeChallengePlan
	} else if code.CodeChallenge == "" && code.CodeChallengeMethod != "" {
		return nil, oauth.ErrInvalidRequest
	}
	return code, nil
}

func (c AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}
