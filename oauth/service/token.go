package service

import (
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

// TokenRepository OAuth2 토큰 저장소
type TokenRepository interface {
	// Save 인자로 받은 엑세스 토큰을 저장하고 저장된 토큰을 fn 함수를 통해 저장된 토큰을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 엑세스 토큰은 리플레시 토큰을 가지지 않는다.
	Save(t *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error
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
	var refresh *entity.RefreshToken
	err = s.tokenRepository.Save(token, func(t *entity.Token) *entity.RefreshToken {
		if c.Type == oauth.ClientTypeConfidential {
			refresh = entity.NewRefreshToken(t, entity.UUIDTokenIDGenerator)
		}
		return refresh
	})
	if err != nil {
		return nil, nil, err
	}
	return token, refresh, nil
}
