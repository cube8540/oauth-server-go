package code

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"oauth-server-go/internal/pkg/oauth"
	"oauth-server-go/oauth/client"
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
	Client              client.Client
	Username            string
	State               string
	Redirect            string
	Scopes              []client.Scope `gorm:"many2many:users.oauth2_code_scope;joinForeignKey:code_id;joinReferences:scope_id"`
	CodeChallenge       oauth.Challenge
	CodeChallengeMethod oauth.ChallengeMethod
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
		return fmt.Errorf("%w: username", ErrParameterMissing)
	}
	c.Username = r.Username
	c.State = r.State
	c.Redirect = r.Redirect
	c.CodeChallenge = r.CodeChallenge
	c.CodeChallengeMethod = r.CodeChallengeMethod
	if c.CodeChallenge != "" && c.CodeChallengeMethod == "" {
		c.CodeChallengeMethod = oauth.ChallengePlan
	} else if c.CodeChallenge == "" && c.CodeChallengeMethod != "" {
		return fmt.Errorf("%w: code challenge", ErrParameterMissing)
	}
	return nil
}

func (c *AuthorizationCode) Verifier(v oauth.Verifier) (bool, error) {
	if c.CodeChallenge != "" {
		switch c.CodeChallengeMethod {
		case oauth.ChallengeS256:
			hash := sha256.New()
			_, err := hash.Write([]byte(v))
			if err != nil {
				return false, fmt.Errorf("codes occurred during hasing %s, %w", v, err)
			}
			encoded := base64.URLEncoding.EncodeToString(hash.Sum(nil))
			return string(c.CodeChallenge) == encoded, nil
		case oauth.ChallengePlan:
			return string(c.CodeChallenge) == string(v), nil
		default:
			return false, nil
		}
	}
	return true, nil
}

func (c *AuthorizationCode) Available() bool {
	return c.ExpiredAt.After(time.Now())
}

func (c AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}
