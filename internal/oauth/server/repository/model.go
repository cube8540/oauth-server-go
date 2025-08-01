package repository

import (
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/pkg/period"
	"oauth-server-go/pkg/sql"
	"time"
)

// Scope OAuth2 스코프 데이터 모델
type Scope struct {
	ID           uint
	Code         string
	Name         string    `gorm:"column:scope_name"`
	Desc         string    `gorm:"column:description"`
	RegisteredAt time.Time `gorm:"column:reg_at"`
}

func (s *Scope) TableName() string {
	return "users.oauth2_scope"
}

// ScopeArray OAuth2 스코프 슬라이스 타입
// 스코프 데이터 모델 슬라이스를 문자열 슬라이스로 변환하는 메소드를 포함한다.
type ScopeArray []Scope

// Array 스코프 데이터 모델 슬라이스를 문자열 슬라이스로 변환한다.
func (s ScopeArray) Array() []string {
	var scopes []string
	for _, s := range s {
		scopes = append(scopes, s.Code)
	}
	return scopes
}

// Client OAuth2 클라이언트 데이터 모델
type Client struct {
	ID           uint
	ClientID     string
	Name         string      `gorm:"column:client_name"`
	Type         client.Type `gorm:"column:client_type"`
	Secret       string
	OwnerID      string
	Redirects    sql.Strings `gorm:"column:redirect_uris"`
	Scopes       ScopeArray  `gorm:"many2many:users.oauth2_client_scope;joinForeignKey:client_id;joinReferences:scope_id"`
	RegisteredAt time.Time   `gorm:"column:reg_at"`
}

func (entity *Client) TableName() string {
	return "users.oauth2_client"
}

// Domain 데이터 모델을 OAuth2 도메인 모델로 변경 한다.
func (entity *Client) Domain() *client.Client {
	c := client.New(entity.ClientID, entity.Secret, entity.Name, entity.Type)

	for _, redirect := range entity.Redirects {
		c.AddRedirect(redirect)
	}

	for _, s := range entity.Scopes {
		c.AddScope(s.Code)
	}

	c.SetRegisteredAt(entity.RegisteredAt)

	return c
}

// AuthorizationCode OAuth2 인가코드 데이터 모델
type AuthorizationCode struct {
	ID                  uint
	Value               string `gorm:"column:code"`
	ClientID            uint
	Client              Client
	Username            string
	State               string
	Redirect            string
	Scopes              ScopeArray `gorm:"many2many:users.oauth2_code_scope;joinForeignKey:code_id;joinReferences:scope_id"`
	CodeChallenge       authorization.Challenge
	CodeChallengeMethod authorization.ChallengeMethod
	IssuedAt, ExpiredAt time.Time
}

func (entity *AuthorizationCode) TableName() string {
	return "users.oauth2_authorization_code"
}

// Domain 데이터 모델을 도메인 모델로 변경 한다.
func (entity *AuthorizationCode) Domain() *authorization.Code {
	c := entity.Client.Domain()

	id := func() string {
		return entity.Value
	}
	cd := authorization.NewCodeWithRange(c, id, period.NewWithStartEnd(entity.IssuedAt, entity.ExpiredAt))

	request := authorization.Request{
		Client:              c.Id(),
		Username:            entity.Username,
		State:               entity.State,
		Scopes:              scope.Join(entity.Scopes.Array()),
		Redirect:            entity.Redirect,
		CodeChallenge:       entity.CodeChallenge,
		CodeChallengeMethod: entity.CodeChallengeMethod,
	}
	_ = cd.CopyFrom(&request)

	return cd
}

// AccessToken OAuth2 엑세스 토큰 데이터 모델
type AccessToken struct {
	ID                  uint
	Value               string `gorm:"column:token"`
	ClientID            uint
	Client              Client
	Username            string
	Scopes              ScopeArray `gorm:"many2many:users.oauth2_token_scope;joinForeignKey:token_id;joinReferences:scope_id"`
	IssuedAt, ExpiredAt time.Time
}

func (entity *AccessToken) TableName() string {
	return "users.oauth2_access_token"
}

// Domain 데이터 모델을 도메인 모델로 변환한다.
func (entity *AccessToken) Domain() *token.AccessToken {
	c := entity.Client.Domain()

	id := func() string {
		return entity.Value
	}
	accessToken := token.NewWithRange(c, id, period.NewWithStartEnd(entity.IssuedAt, entity.ExpiredAt))
	accessToken.ApplyResourceOwnerInfo(entity.Username, entity.Scopes.Array())

	return accessToken
}

// RefreshToken OAuth2 리플레시 토큰 데이터 모델
type RefreshToken struct {
	ID                  uint
	Value               string `gorm:"column:token"`
	AccessTokenID       uint   `gorm:"column:access_token_id"`
	AccessToken         *AccessToken
	IssuedAt, ExpiredAt time.Time
}

func (entity *RefreshToken) TableName() string {
	return "users.oauth2_refresh_token"
}

// Domain 데이터 모델을 도메인 모델로 변경한다.
func (entity *RefreshToken) Domain() *token.RefreshToken {
	accessToken := entity.AccessToken.Domain()

	id := func() string {
		return entity.Value
	}
	return token.NewRefreshTokenWithRange(accessToken, id, period.NewWithStartEnd(entity.IssuedAt, entity.ExpiredAt))
}
