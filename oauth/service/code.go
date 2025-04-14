package service

import (
	"errors"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

var codeGenerator entity.AuthCodeGenerator

func init() {
	codeGenerator = entity.UUIDAuthCodeGenerator
}

type AuthCodeRepository interface {
	Save(c *entity.AuthorizationCode) error
	Delete(c *entity.AuthorizationCode) error
	FindByCode(code string) (*entity.AuthorizationCode, error)
}

type AuthCodeService struct {
	repository AuthCodeRepository
}

func NewAuthCodeService(r AuthCodeRepository) *AuthCodeService {
	return &AuthCodeService{
		repository: r,
	}
}

func (s *AuthCodeService) New(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.AuthorizationCode, error) {
	scopes, err := c.Scopes.GetAll(oauth.SplitScope(r.Scopes))
	if err != nil {
		return nil, err
	}
	code := entity.NewAuthCode(codeGenerator)
	code.ClientID = c.ID
	code.Scopes = scopes
	if err = code.Set(r); err != nil {
		return nil, err
	}
	if err = s.repository.Save(code); err != nil {
		return nil, err
	}
	return code, nil
}

func (s *AuthCodeService) Retrieve(code string) (*entity.AuthorizationCode, error) {
	authCode, err := s.repository.FindByCode(code)
	if errors.Is(err, oauth.ErrAuthorizationCodeNotFound) {
		return nil, oauth.NewErr(oauth.ErrInvalidGrant, "authorization code is not found")
	}
	if err != nil {
		return nil, err
	}
	scopes := authCode.Scopes
	if err = s.repository.Delete(authCode); err != nil {
		return nil, err
	}
	authCode.Scopes = scopes
	return authCode, nil
}
