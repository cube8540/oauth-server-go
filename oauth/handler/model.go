package handler

import (
	"oauth-server-go/oauth/entity"
	"time"
)

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
