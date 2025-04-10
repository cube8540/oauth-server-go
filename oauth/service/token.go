package service

import (
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

// TokenRepository OAuth2 토큰 저장소
type TokenRepository interface {
	Save(t *entity.Token) error
}

// AuthCodeConsume 인자로 인가코드를 받아 그 인가코드의 엔티티 반환하고 저장소에서 삭제한다.
type AuthCodeConsume func(code string) (*entity.AuthorizationCode, error)

type AuthorizationCodeFlow struct {
	tokenRepository TokenRepository
	consume         AuthCodeConsume
}

func NewAuthorizationCodeFlow(tr TokenRepository, consume AuthCodeConsume) *AuthorizationCodeFlow {
	return &AuthorizationCodeFlow{
		tokenRepository: tr,
		consume:         consume,
	}
}

func (s AuthorizationCodeFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	if r.Code == "" {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "authorization code is required")
	}
	code, err := s.consume(r.Code)
	if err != nil {
		return nil, nil, err
	}
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
	if to, _ := c.RedirectURL(code.Redirect); to != r.Redirect {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "redirect_uri is not matched")
	}
	token := entity.NewToken(entity.UUIDTokenIDGenerator, code)
	if err = s.tokenRepository.Save(token); err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}
