package service

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

type TokenIssueService struct {
	AuthorizationCodeFlow func(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error)
}

func NewTokenIssueService() *TokenIssueService {
	return &TokenIssueService{
		AuthorizationCodeFlow: authorizationCodeFlow,
	}
}

func authorizationCodeFlow(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	if r.Code == "" {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "authorization code is required")
	}
	code, err := getCode(r.Code)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "authorization code is not found")
	}
	if err != nil {
		return nil, nil, err
	}
	if code == nil {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidGrant, "authorization code is not found")
	}
	defer func() {
		_ = deleteCode(code)
	}()
	if code.ClientID != c.ID {
		return nil, nil, oauth.NewErr(oauth.ErrUnauthorizedClient, "authorization code client is different")
	}
	if !code.Available() {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidGrant, "authorization code is expires")
	}
	verifier, err := code.Verifier(r.CodeVerifier)
	if err != nil {
		return nil, nil, err
	}
	if !verifier {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "code_verifier is not matched")
	}
	to, _ := c.RedirectURL(code.Redirect)
	if to != r.Redirect {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "redirect_uri is not matched")
	}
	token := entity.NewToken(entity.UUIDTokenIDGenerator, code)
	err = tokenRepository.Save(token)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}
