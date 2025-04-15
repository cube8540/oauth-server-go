package entity

import (
	"github.com/google/uuid"
	"strings"
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

type Range struct {
	IssuedAt, ExpiredAt time.Time
}

func (r *Range) IsActive() bool {
	return r.ExpiredAt.After(time.Now())
}

func (r *Range) GetIssuedAt() uint {
	return uint(r.IssuedAt.Unix())
}

func (r *Range) GetExpiredAt() uint {
	if r.IsActive() {
		now := time.Now()
		return uint(r.ExpiredAt.Sub(now) / time.Second)
	}
	return 0
}

func newRange(expires time.Duration) Range {
	now := time.Now()
	return Range{
		IssuedAt:  now,
		ExpiredAt: now.Add(expires),
	}
}

// Token 토큰
type Token struct {
	ID       uint
	Value    string `gorm:"column:token"`
	ClientID uint
	Client   Client
	Username string
	Scopes   GrantedScopes `gorm:"many2many:users.oauth2_token_scope;joinForeignKey:token_id;joinReferences:scope_id"`
	Range
}

func (t *Token) GetValue() string {
	return t.Value
}

func (t *Token) GetClientID() string {
	return t.Client.ClientID
}

func (t *Token) GetUsername() string {
	return t.Username
}

func (t *Token) GetScopes() string {
	var scopes []string
	for _, scope := range t.Scopes {
		scopes = append(scopes, scope.Code)
	}
	return strings.Join(scopes, " ")
}

func (t Token) TableName() string {
	return "users.oauth2_access_token"
}

func NewTokenWithCode(gen TokenIDGenerator, c *AuthorizationCode) *Token {
	return &Token{
		Value:    gen(),
		ClientID: c.ClientID,
		Username: c.Username,
		Scopes:   c.Scopes,
		Range:    newRange(tokenExpiresMinute),
	}
}

func NewToken(gen TokenIDGenerator, c *Client) *Token {
	return &Token{
		Value:    gen(),
		ClientID: c.ID,
		Range:    newRange(tokenExpiresMinute),
	}
}

// RefreshToken OAuth2 리프레시 토큰
type RefreshToken struct {
	ID      uint
	Value   string `gorm:"column:token"`
	TokenID uint   `gorm:"column:access_token_id"`
	Token   Token
	Range
}

func (t *RefreshToken) GetValue() string {
	return t.Value
}

func (t *RefreshToken) GetClientID() string {
	return t.Token.GetClientID()
}

func (t *RefreshToken) GetUsername() string {
	return t.Token.GetUsername()
}

func (t *RefreshToken) GetScopes() string {
	return t.Token.GetScopes()
}

func (t RefreshToken) TableName() string {
	return "users.oauth2_refresh_token"
}

func NewRefreshToken(t *Token, gen TokenIDGenerator) *RefreshToken {
	return &RefreshToken{
		Value:   gen(),
		TokenID: t.ID,
		Range:   newRange(refreshExpiresMinute),
	}
}
