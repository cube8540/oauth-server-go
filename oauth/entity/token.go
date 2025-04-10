package entity

import (
	"github.com/google/uuid"
	"time"
)

// tokenExpiresMinute OAuth2 토큰 만료 시간
// 10분으로 설정
const tokenExpiresMinute = time.Minute * 10

// refreshExpiresMinute OAuth2 리프레시 토큰 만료
// 7일로 설정
const refreshExpiresMinute = time.Hour * 24 * 7

// TokenIDGenerator 토큰 생성 함수
type TokenIDGenerator func() string

// UUIDTokenIDGenerator UUID 토큰 생성기
var UUIDTokenIDGenerator = func() string {
	return uuid.New().String()
}

// Token 토큰
type Token struct {
	ID                  uint
	Value               string `gorm:"column:token"`
	ClientID            uint
	Client              Client
	Username            string
	Scopes              []Scope `gorm:"many2many:users.oauth2_token_scopes"`
	IssuedAt, ExpiredAt time.Time
}

func (t Token) TableName() string {
	return "users.oauth2_access_token"
}

func NewToken(gen TokenIDGenerator, c *AuthorizationCode) *Token {
	now := time.Now()
	return &Token{
		Value:     gen(),
		ClientID:  c.ClientID,
		Username:  c.Username,
		Scopes:    c.Scopes,
		IssuedAt:  now,
		ExpiredAt: now.Add(tokenExpiresMinute),
	}
}

// RefreshToken OAuth2 리프레시 토큰
type RefreshToken struct {
	ID                  uint
	Value               string `gorm:"column:token"`
	TokenID             uint   `gorm:"column:access_token_id"`
	Token               Token
	IssuedAt, ExpiredAt time.Time
}

func NewRefreshToken(t *Token, gen TokenIDGenerator) *RefreshToken {
	now := time.Now()
	return &RefreshToken{
		Value:     gen(),
		TokenID:   t.ID,
		IssuedAt:  now,
		ExpiredAt: now.Add(refreshExpiresMinute),
	}
}

func (t RefreshToken) TableName() string {
	return "users.oauth2_refresh_token"
}
