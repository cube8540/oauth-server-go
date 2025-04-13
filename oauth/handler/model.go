package handler

import (
	"oauth-server-go/oauth/entity"
	"time"
)

// TokenDetails 사용자에게 발급된 토큰의 상세 정보를 제공하는 구조체이다. 클라이언트 측에 표시할 때 사용된다.
type TokenDetails struct {
	Value      string    `json:"value"`
	ClientName string    `json:"clientName"`
	Active     bool      `json:"active"`
	Scopes     []string  `json:"scopes"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiredAt  time.Time `json:"expiredAt"`
}

func NewTokenDetails(t *entity.Token) TokenDetails {
	var scopes []string
	for _, scope := range t.Scopes {
		scopes = append(scopes, scope.Code)
	}
	return TokenDetails{
		Value:      t.Value,
		ClientName: t.Client.Name,
		Active:     t.InspectActive(),
		Scopes:     scopes,
		IssuedAt:   t.IssuedAt,
		ExpiredAt:  t.ExpiredAt,
	}
}
