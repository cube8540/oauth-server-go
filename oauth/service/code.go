package service

import (
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

var codeGenerator entity.AuthCodeGenerator

func init() {
	codeGenerator = entity.UUIDAuthCodeGenerator
}

type AuthCodeService struct {
	New func(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.AuthorizationCode, error)
}

func NewAuthCodeService() *AuthCodeService {
	return &AuthCodeService{
		New: newAuthCode,
	}
}

func newAuthCode(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.AuthorizationCode, error) {
	scopes, err := c.GetScopes(r.SplitScope())
	if err != nil {
		return nil, err
	}
	code := entity.NewAuthCode(codeGenerator)
	code.ClientID = c.ID
	code.Scopes = scopes
	err = code.Set(r)
	if err != nil {
		return nil, err
	}
	if err = authCodeRepository.Save(code); err != nil {
		return nil, err
	}
	return code, nil
}

func getCode(c string) (*entity.AuthorizationCode, error) {
	return authCodeRepository.FindByCode(c)
}

func deleteCode(c *entity.AuthorizationCode) error {
	return authCodeRepository.Delete(c)
}
